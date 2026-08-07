package webtest

import (
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

// WhoisResult 包含 WHOIS 查询的结构化结果
// 与前端 whois.vue 的结构体保持一致
type WhoisResult struct {
	Domain       string         `json:"domain"`       // 域名（大写）
	Status       []string       `json:"status"`       // 域名状态列表
	Registrar    WhoisRegistrar `json:"registrar"`    // 注册商信息
	Registrant   WhoisContact   `json:"registrant"`   // 注册人信息
	Technical    WhoisContact   `json:"technical"`    // 技术联系人
	AbuseContact WhoisContact   `json:"abuseContact"` // Abuse 联系人
	Dates        WhoisDates     `json:"dates"`        // 关键日期
	NameServers  []string       `json:"nameservers"`  // DNS 服务器列表
	WhoisServer  string         `json:"whoisServer"`  // Whois 服务器地址
	Raw          string         `json:"raw"`          // 原始响应文本
	Error        string         `json:"error"`        // 错误信息
}

type WhoisRegistrar struct {
	Name   string `json:"name"`
	IanaId string `json:"ianaId"`
}

type WhoisContact struct {
	Name       string `json:"name"`
	Org        string `json:"org"`
	Phone      string `json:"phone"`
	Email      string `json:"email"`
	Province   string `json:"province"`
	ContactUri string `json:"contactUri"`
}

type WhoisDates struct {
	Registration string `json:"registration"`
	Expiration   string `json:"expiration"`
	LastChanged  string `json:"lastChanged"`
}

// QueryWhois 执行 WHOIS 查询并解析结构化数据
// 使用 likexian/whois 库查询原始响应，再用 whois-parser 解析为结构化数据
// 对于 DNS 负载均衡且部分 IP 不可达的 WHOIS 服务器（如 whois.nic.top），
// 首次失败后会解析所有 IP 逐个尝试连接
func QueryWhois(domain string) (*WhoisResult, error) {
	raw, err := whois.Whois(domain)
	if err != nil {
		raw, err = whoisRetryWithFallback(domain, err)
	}
	result := parseWhoisResult(domain, raw)
	result.Error = errString(err)
	return result, nil
}

// errString safely converts an error to string
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// whoisRetryWithFallback 在 whois.Whois 失败后，手动解析 WHOIS 服务器所有 IP 逐个尝试
func whoisRetryWithFallback(domain string, firstErr error) (string, error) {
	// 先查 IANA 获取该域名后缀对应的 WHOIS 服务器
	ianaResult, err := whois.Whois("."+getExtension(domain))
	if err != nil {
		return "", firstErr
	}

	server := extractWhoisServer(ianaResult)
	if server == "" {
		return "", firstErr
	}

	// 解析该服务器的所有 IP
	ips, err := netLookupIP(server)
	if err != nil {
		return "", firstErr
	}

	// 逐个 IP 尝试连接
	lastErr := firstErr
	for _, ip := range ips {
		raw, err := rawWhoisQuery(domain, ip.String(), "43")
		if err == nil {
			return raw, nil
		}
		lastErr = err
	}

	return "", lastErr
}

// getExtension 提取域名后缀
func getExtension(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return domain
}

// extractWhoisServer 从 IANA 响应中提取 WHOIS 服务器地址
func extractWhoisServer(data string) string {
	for _, token := range []string{"whois: ", "Whois: "} {
		if idx := strings.Index(data, token); idx != -1 {
			start := idx + len(token)
			end := strings.Index(data[start:], "\n")
			if end == -1 {
				end = len(data) - start
			}
			server := strings.TrimSpace(data[start : start+end])
			server = strings.TrimPrefix(server, "http://")
			server = strings.TrimPrefix(server, "https://")
			server = strings.TrimPrefix(server, "whois://")
			server = strings.TrimSuffix(server, "/")
			return server
		}
	}
	return ""
}

// netLookupIP 解析域名的所有 IP 地址
func netLookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

// rawWhoisQuery 直接向指定 IP:port 发送 WHOIS 查询
func rawWhoisQuery(domain, server, port string) (string, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.Dial("tcp", net.JoinHostPort(server, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, err = conn.Write([]byte(domain + "\r\n"))
	if err != nil {
		return "", err
	}

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}
	return string(buf[:n]), nil
}

// parseWhoisResult 用 whois-parser 解析原始响应，转换为前端需要的格式
func parseWhoisResult(domain, raw string) *WhoisResult {
	info, err := whoisparser.Parse(raw)
	result := &WhoisResult{
		Domain: strings.ToUpper(domain),
	}

	if err != nil || info.Domain == nil {
		result.Raw = raw
		return result
	}

	// Domain 字段
	result.NameServers = info.Domain.NameServers
	result.Status = info.Domain.Status
	result.Dates.Registration = info.Domain.CreatedDate
	result.Dates.Expiration = info.Domain.ExpirationDate
	result.Dates.LastChanged = info.Domain.UpdatedDate
	result.WhoisServer = info.Domain.WhoisServer

	// Registrar
	if info.Registrar != nil {
		result.Registrar.Name = info.Registrar.Name
		result.Registrar.IanaId = extractIanaIdFromRaw(raw)
	}

	// Registrant
	if info.Registrant != nil {
		result.Registrant = contactFromParser(info.Registrant)
	}

	// Technical
	if info.Technical != nil {
		result.Technical = contactFromParser(info.Technical)
	}

	// AbuseContact: 从原始响应手动提取，不用 Administrative 映射
	abuse := extractAbuseContactFromRaw(raw)
	if abuse != nil {
		result.AbuseContact = *abuse
	}

	result.Raw = raw
	return result
}

// isEmptyContact 检查联系信息是否全为空
func isEmptyContact(c WhoisContact) bool {
	return c.Name == "" && c.Org == "" && c.Phone == "" && c.Email == "" && c.Province == "" && c.ContactUri == ""
}

// abusePatterns 用于从原始 WHOIS 文本中提取 Abuse 联系信息
// 匹配字段名（不区分大小写），如:
//   Registrar Abuse Contact Email: abuse@example.com
//   Abuse Phone: +1.1234567890
var abusePatterns = map[string]*regexp.Regexp{
	"email": regexp.MustCompile(`(?i)^\s*(?:Registrar\s+Abuse\s+Contact\s+Email|Abuse\s+(?:Contact\s+)?Email)\s*[:=]\s*(.+?)\s*$`),
	"phone": regexp.MustCompile(`(?i)^\s*(?:Registrar\s+Abuse\s+Contact\s+Phone|Abuse\s+(?:Contact\s+)?Phone)\s*[:=]\s*(.+?)\s*$`),
}

// extractAbuseContactFromRaw 从原始 WHOIS 响应中手动提取 Abuse 联系人信息
// whois-parser 没有专门的 Abuse contact 字段，需要从原始文本解析
func extractAbuseContactFromRaw(raw string) *WhoisContact {
	lines := strings.Split(raw, "\n")
	var abuse WhoisContact

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if matches := abusePatterns["email"].FindStringSubmatch(line); len(matches) == 2 {
			abuse.Email = matches[1]
			continue
		}

		if matches := abusePatterns["phone"].FindStringSubmatch(line); len(matches) == 2 {
			abuse.Phone = matches[1]
			continue
		}
	}

	if !isEmptyContact(abuse) {
		return &abuse
	}
	return nil
}

// contactFromParser 将 whois-parser 的 Contact 转换为前端需要的格式
func contactFromParser(c *whoisparser.Contact) WhoisContact {
	return WhoisContact{
		Name:       c.Name,
		Org:        c.Organization,
		Phone:      c.Phone,
		Email:      c.Email,
		Province:   c.Province,
		ContactUri: c.ReferralURL,
	}
}

// ianaIdPattern 匹配 Registrar IANA ID 字段（RFC 格式）
var ianaIdPattern = regexp.MustCompile(`(?i)^\s*Registrar\s+IANA\s+ID\s*[:=]\s*(\S+)`)

// extractIanaIdFromRaw 从原始 WHOIS 响应中提取 Registrar IANA ID
// whois-parser 未提供该字段，需手动解析
func extractIanaIdFromRaw(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if matches := ianaIdPattern.FindStringSubmatch(line); len(matches) == 2 {
			return matches[1]
		}
	}
	return ""
}

// ASNWhoisResult 包含 ASN WHOIS 查询的结构化结果
type ASNWhoisResult struct {
	ASNumber    string `json:"asNumber"`
	ASName      string `json:"asName"`
	OrgName     string `json:"orgName"`
	OrgID       string `json:"orgId"`
	Country     string `json:"country"`
	RegDate     string `json:"regDate"`
	Updated     string `json:"updated"`
	AbuseName   string `json:"abuseName"`
	AbuseEmail  string `json:"abuseEmail"`
	AbusePhone  string `json:"abusePhone"`
	Raw         string `json:"raw"`
	Error       string `json:"error"`
}

// asnFieldPatterns 用于从原始 ASN WHOIS 文本中提取字段
var asnFieldPatterns = map[string]*regexp.Regexp{
	"asNumber":    regexp.MustCompile(`(?i)^\s*ASNumber\s*[:=]\s*(.+?)\s*$`),
	"asName":      regexp.MustCompile(`(?i)^\s*ASName\s*[:=]\s*(.+?)\s*$`),
	"asHandle":    regexp.MustCompile(`(?i)^\s*ASHandle\s*[:=]\s*(.+?)\s*$`),
	"regDate":     regexp.MustCompile(`(?i)^\s*RegDate\s*[:=]\s*(.+?)\s*$`),
	"updated":     regexp.MustCompile(`(?i)^\s*Updated\s*[:=]\s*(.+?)\s*$`),
	"orgName":     regexp.MustCompile(`(?i)^\s*OrgName\s*[:=]\s*(.+?)\s*$`),
	"orgId":       regexp.MustCompile(`(?i)^\s*OrgId\s*[:=]\s*(.+?)\s*$`),
	"country":     regexp.MustCompile(`(?i)^\s*Country\s*[:=]\s*([A-Z]{2})\s*$`),
	"abuseName":   regexp.MustCompile(`(?i)^\s*OrgAbuseName\s*[:=]\s*(.+?)\s*$`),
	"abuseEmail":  regexp.MustCompile(`(?i)^\s*OrgAbuseEmail\s*[:=]\s*(.+?)\s*$`),
	"abusePhone":  regexp.MustCompile(`(?i)^\s*OrgAbusePhone\s*[:=]\s*(.+?)\s*$`),
}

// parseASNWhoisRaw 从原始 ASN WHOIS 响应中解析结构化数据
func parseASNWhoisRaw(raw string) *ASNWhoisResult {
	result := &ASNWhoisResult{Raw: raw}
	lines := strings.Split(raw, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		for field, pattern := range asnFieldPatterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) == 2 {
				switch field {
				case "asNumber":
					result.ASNumber = matches[1]
				case "asName":
					result.ASName = matches[1]
				case "asHandle":
					if result.ASNumber == "" {
						result.ASNumber = strings.TrimPrefix(matches[1], "AS")
					}
				case "regDate":
					result.RegDate = matches[1]
				case "updated":
					result.Updated = matches[1]
				case "orgName":
					result.OrgName = matches[1]
				case "orgId":
					result.OrgID = matches[1]
				case "country":
					result.Country = matches[1]
				case "abuseName":
					result.AbuseName = matches[1]
				case "abuseEmail":
					result.AbuseEmail = matches[1]
				case "abusePhone":
					result.AbusePhone = matches[1]
				}
			}
		}
	}

	return result
}

// QueryASNWhois 执行 ASN WHOIS 查询并解析结构化数据
// 使用 likexian/whois 库查询 ARIN WHOIS 服务器获取 ASN 详细信息
func QueryASNWhois(asn string) (*ASNWhoisResult, error) {
	// 确保 ASN 格式为 "AS" + 数字
	asn = strings.TrimSpace(asn)
	if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
		asn = "AS" + asn
	}

	raw, err := whois.Whois(asn)
	if err != nil {
		return &ASNWhoisResult{
			ASNumber: strings.TrimPrefix(asn, "AS"),
			Error:    err.Error(),
		}, nil
	}

	result := parseASNWhoisRaw(raw)
	result.Raw = raw
	return result, nil
}
