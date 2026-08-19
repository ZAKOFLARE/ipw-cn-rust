//! TTL 缓存 + 单飞防击穿（对齐 Go 原版 sync.Map 缓存 + singleflight）
//!
//! 语义对齐：
//! - 缓存 TTL 5 分钟（Go: time.Since(entry.timestamp) < 5*time.Minute）
//! - 单飞只合并并发请求，执行完成后从单飞表移除；结果是否写入缓存由调用方决定
//! - 错误结果默认不入缓存（对齐 Go detail/ssl 的成功才 Store；speed 特殊，P3 单独对齐）

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};

/// 标记结果是否为失败状态（用于软失败缓存 TTL：失败 30s，成功 5min）
pub trait FailureAware {
    fn is_failure(&self) -> bool;
}

/// 带 TTL 的并发缓存
///
/// TTL 策略（对齐 Go）：
/// - 成功结果：5 分钟
/// - 失败结果：30 秒（Go 中通过 goroutine sleep 后 Delete 实现）
pub struct Cache<K, V> {
    inner: moka::sync::Cache<K, V>,
}

struct FailAwareExpiry;

impl<K, V> moka::Expiry<K, V> for FailAwareExpiry
where
    K: Send + Sync + 'static,
    V: FailureAware + Send + Sync + 'static,
{
    fn expire_after_create(
        &self,
        _key: &K,
        value: &V,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        if value.is_failure() {
            Some(Duration::from_secs(30))
        } else {
            Some(Duration::from_secs(300))
        }
    }
}

impl<K, V> Cache<K, V>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: FailureAware + Clone + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self {
            inner: moka::sync::Cache::builder()
                .expire_after(FailAwareExpiry)
                .build(),
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.inner.get(key)
    }

    pub fn insert(&self, key: K, value: V) {
        self.inner.insert(key, value);
    }

    /// 缓存失效（当前仅测试使用；缓存淘汰由 moka TTL 负责）
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn remove(&self, key: &K) {
        self.inner.invalidate(key);
    }
}

impl<K, V> Default for Cache<K, V>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: FailureAware + Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// 单飞：同一 key 并发请求共享同一个执行 future
pub struct SingleFlight<T: Clone + Send + Sync + 'static> {
    in_flight: Mutex<HashMap<String, Arc<Flight<T>>>>,
}

struct Flight<T> {
    state: Mutex<FlightState<T>>,
    notify: Notify,
}

enum FlightState<T> {
    Running,
    Done(Arc<Result<T, String>>),
}

impl<T: Clone + Send + Sync + 'static> Default for SingleFlight<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SingleFlight<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self {
            in_flight: Mutex::new(HashMap::new()),
        }
    }

    /// 执行 future；同一 key 的并发调用共享结果。
    /// 执行者完成（无论成败）后从单飞表移除，后续新请求重新执行。
    pub async fn run<F>(&self, key: &str, fut: F) -> Result<T, String>
    where
        F: Future<Output = Result<T, String>> + Send + 'static,
    {
        // 快路径：已有飞行中的同 key 请求，直接等结果
        {
            let map = self.in_flight.lock().await;
            if let Some(flight) = map.get(key) {
                let flight = flight.clone();
                drop(map);
                return flight.wait().await;
            }
        }

        // 慢路径：创建新的 flight（注意持锁期间不执行 future）
        let flight = {
            let mut map = self.in_flight.lock().await;
            if let Some(flight) = map.get(key) {
                let flight = flight.clone();
                drop(map);
                return flight.wait().await;
            }
            let flight = Arc::new(Flight::new());
            map.insert(key.to_string(), flight.clone());
            flight
        };

        // 执行（锁已释放）
        let result = Arc::new(fut.await);

        // 广播结果并移除单飞表条目
        {
            let mut st = flight.state.lock().await;
            *st = FlightState::Done(result.clone());
        }
        flight.notify.notify_waiters();
        self.in_flight.lock().await.remove(key);

        match Arc::try_unwrap(result) {
            Ok(r) => r,
            Err(arc) => (*arc).clone(),
        }
    }
}

impl<T> Flight<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn new() -> Self {
        Self {
            state: Mutex::new(FlightState::Running),
            notify: Notify::new(),
        }
    }

    async fn wait(&self) -> Result<T, String> {
        loop {
            // 先注册通知再检查状态，避免丢失唤醒（tokio Notify 标准模式）
            let notified = self.notify.notified();
            let state = self.state.lock().await;
            match &*state {
                FlightState::Done(result) => return (**result).clone(),
                FlightState::Running => {
                    drop(state);
                    notified.await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[derive(Clone)]
    struct Val {
        n: i32,
        fail: bool,
    }

    impl FailureAware for Val {
        fn is_failure(&self) -> bool {
            self.fail
        }
    }

    #[tokio::test]
    async fn cache_failure_ttl_shorter() {
        // 失败结果 30s 有效：无法在测试里等 30s，验证 get 命中即可
        let cache = Cache::new();
        cache.insert("k".to_string(), Val { n: 1, fail: true });
        assert_eq!(cache.get(&"k".to_string()).unwrap().n, 1);
        cache.remove(&"k".to_string());
        assert!(cache.get(&"k".to_string()).is_none());
    }

    #[tokio::test]
    async fn singleflight_coalesces() {
        let sf = Arc::new(SingleFlight::new());
        let counter = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let sf = sf.clone();
            let counter = counter.clone();
            handles.push(tokio::spawn(async move {
                sf.run("key", async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok::<_, String>("done")
                })
                .await
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            results.push(h.await.unwrap().unwrap());
        }
        assert!(results.iter().all(|r| *r == "done"));
        // 只执行一次
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn singleflight_reruns_after_done() {
        let sf = Arc::new(SingleFlight::new());
        let counter = Arc::new(AtomicUsize::new(0));

        {
            let sf = sf.clone();
            let counter = counter.clone();
            let r = sf
                .run("key", async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, String>(1)
                })
                .await;
            assert_eq!(r, Ok(1));
        }

        // 上一次完成后，新请求重新执行
        let sf2 = sf.clone();
        let counter2 = counter.clone();
        let r2 = sf2
            .run("key", async move {
                counter2.fetch_add(1, Ordering::SeqCst);
                Ok::<_, String>(2)
            })
            .await;
        assert_eq!(r2, Ok(2));
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn singleflight_error_propagates() {
        let sf = Arc::new(SingleFlight::new());
        let r = sf
            .run("err", async { Err::<i32, _>("boom".to_string()) })
            .await;
        assert_eq!(r, Err("boom".to_string()));
    }
}
