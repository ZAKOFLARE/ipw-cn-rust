package webtest

import (
	"fmt"
	"math"
	"net"
	"time"
)

// UDPingResult 包含 UDP 探测测试的结果
type UDPingResult struct {
	IP        string    `json:"ip"`
	Port      string    `json:"port"`
	Success   bool      `json:"success"`
	RTT       float64   `json:"rtt"`
	Error     string    `json:"error"`
	Timestamp time.Time `json:"timestamp"`
}

// UDPingStats 包含多次 UDP 探测测试的统计信息
type UDPingStats struct {
	IP       string         `json:"ip"`
	Port     string         `json:"port"`
	Sent     int            `json:"sent"`
	Success  int            `json:"success"`
	LossRate float64        `json:"loss_rate"`
	MaxRTT   float64        `json:"max_rtt"`
	MinRTT   float64        `json:"min_rtt"`
	AvgRTT   float64        `json:"avg_rtt"`
	Results  []UDPingResult `json:"results"`
}

// UDPing 执行单次 UDP 探测测试
// 向目标主机的指定端口发送一个 UDP 数据包，等待响应来判断端口是否可达。
func UDPing(host string, port string, version string, timeout time.Duration) (*UDPingResult, error) {
	ip, err := resolveHost(host, version)
	if err != nil {
		return nil, err
	}

	addr := ""
	switch version {
	case "v4":
		addr = fmt.Sprintf("%s:%s", ip, port)
	case "v6":
		addr = fmt.Sprintf("[%s]:%s", ip, port)
	}

	// 创建 UDP 连接（使用 "udp4"/"udp6" 强制协议版本）
	network := "udp"
	if version == "v4" {
		network = "udp4"
	} else if version == "v6" {
		network = "udp6"
	}

	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return &UDPingResult{
			IP:        ip,
			Port:      port,
			Success:   false,
			RTT:       -1,
			Error:     err.Error(),
			Timestamp: time.Now(),
		}, nil
	}
	defer conn.Close()

	// 设置读写截止时间
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)

	// 发送探测数据包
	payload := []byte("udping probe")
	start := time.Now()
	_, err = conn.Write(payload)
	if err != nil {
		return &UDPingResult{
			IP:        ip,
			Port:      port,
			Success:   false,
			RTT:       -1,
			Error:     fmt.Sprintf("write failed: %v", err),
			Timestamp: start,
		}, nil
	}

	// 尝试读取响应
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)

	rtt := time.Since(start).Seconds() * 1000

	result := &UDPingResult{
		IP:        ip,
		Port:      port,
		Timestamp: start,
	}

	if err != nil {
		// 读取失败通常是因为超时或收到 ICMP 端口不可达
		result.Success = false
		result.RTT = -1
		result.Error = err.Error()
	} else {
		result.Success = true
		result.RTT = math.Round(rtt*100) / 100
	}

	return result, nil
}

// UDPingRun 执行多次 UDP 探测测试并返回统计结果
func UDPingRun(host string, port string, count int, version string, timeout time.Duration, interval time.Duration) (*UDPingStats, error) {
	ip, err := resolveHost(host, version)
	if err != nil {
		return &UDPingStats{
			IP:       "Error: " + err.Error(),
			Port:     port,
			Sent:     count,
			Success:  0,
			Results:  nil,
			MinRTT:   -1,
			MaxRTT:   -1,
			AvgRTT:   -1,
			LossRate: 100,
		}, nil
	}

	stats := &UDPingStats{
		IP:      ip,
		Port:    port,
		Sent:    count,
		MinRTT:  math.MaxFloat64,
		Results: make([]UDPingResult, 0, count),
	}

	var totalRTT float64
	successCount := 0

	for i := 0; i < count; i++ {
		result, err := UDPing(host, port, version, timeout)
		if err != nil {
			return nil, err
		}

		stats.Results = append(stats.Results, *result)

		if result.Success {
			successCount++
			totalRTT += result.RTT
			if result.RTT > stats.MaxRTT {
				stats.MaxRTT = result.RTT
			}
			if result.RTT < stats.MinRTT {
				stats.MinRTT = result.RTT
			}
		}

		if i < count-1 && interval > 0 {
			time.Sleep(interval)
		}
	}

	stats.Success = successCount
	stats.LossRate = math.Round(float64(count-successCount)*10000/float64(count)) / 100

	if successCount > 0 {
		stats.AvgRTT = math.Round(totalRTT*100/float64(successCount)) / 100
	} else {
		stats.MinRTT = -1
		stats.MaxRTT = -1
		stats.AvgRTT = -1
	}

	return stats, nil
}
