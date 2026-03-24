package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
)

// ============================================================
// Structs DNS / Email
// ============================================================

type SPFRecord struct {
	Raw []string
}

type DKIMRecord struct {
	Raw  string            `json:"raw,omitempty"`
	Tags map[string]string `json:"tags,omitempty"`
}

// DMARCRecord est notre parser DMARC stdlib pur (pas de dépendance externe).
type DMARCRecord struct {
	Policy          string
	SubdomainPolicy string
	SPFAlignment    string
	DKIMAlignment   string
	Percentage      int
	RUA             []string
	RUF             []string
}

type DMARCInfo struct {
	Raw    string
	Record DMARCRecord
}

type SPFNetwork struct {
	CIDR   string `json:"cidr"`
	Source string `json:"source"`
}

type EmailExtract struct {
	HeaderFrom   string   `json:"header_from,omitempty"`
	MailFrom     string   `json:"mailfrom,omitempty"`
	DKIMDomain   string   `json:"dkim_domain,omitempty"`
	DKIMSelector string   `json:"dkim_selector,omitempty"`
	ClientIPs    []string `json:"client_ips,omitempty"`
}

// ============================================================
// Structs JSON de sortie
// ============================================================

type JSONSPFCheck struct {
	IP       string `json:"ip,omitempty"`
	MailFrom string `json:"mailfrom,omitempty"`
	Helo     string `json:"helo,omitempty"`
	Result   string `json:"result,omitempty"`
	Error    string `json:"error,omitempty"`
}

type JSONDKIMSignature struct {
	Domain   string `json:"domain,omitempty"`
	Selector string `json:"selector,omitempty"`
	Valid    bool   `json:"valid"`
	Error    string `json:"error,omitempty"`
}

type JSONAlignment struct {
	FromDomain     string `json:"from_domain,omitempty"`
	MailFromDomain string `json:"mailfrom_domain,omitempty"`
	DKIMDomain     string `json:"dkim_domain,omitempty"`
	ASPF           string `json:"aspf,omitempty"`
	ADKIM          string `json:"adkim,omitempty"`
	SPFAligned     bool   `json:"spf_aligned"`
	DKIMAligned    bool   `json:"dkim_aligned"`
}

type JSONDMARC struct {
	Raw             string   `json:"raw,omitempty"`
	Policy          string   `json:"policy,omitempty"`
	SubdomainPolicy string   `json:"subdomain_policy,omitempty"`
	ASPF            string   `json:"aspf,omitempty"`
	ADKIM           string   `json:"adkim,omitempty"`
	RUA             []string `json:"rua,omitempty"`
	RUF             []string `json:"ruf,omitempty"`
	Pct             int      `json:"pct,omitempty"`
}

type JSONDMARCResult struct {
	Evaluated       bool   `json:"evaluated"`
	Pass            bool   `json:"pass"`
	SPFPass         bool   `json:"spf_pass"`
	SPFAligned      bool   `json:"spf_aligned"`
	DKIMPass        bool   `json:"dkim_pass"`
	DKIMAligned     bool   `json:"dkim_aligned"`
	Reason          string `json:"reason,omitempty"`
	Policy          string `json:"policy,omitempty"`
	EffectivePolicy string `json:"effective_policy,omitempty"`
	Pct             int    `json:"pct,omitempty"`
	Action          string `json:"action,omitempty"`
}

type JSONAutofill struct {
	Enabled   bool          `json:"enabled"`
	FromEmail *EmailExtract `json:"from_email,omitempty"`
	Used      struct {
		HeaderFrom   string `json:"header_from,omitempty"`
		MailFrom     string `json:"mailfrom,omitempty"`
		DKIMDomain   string `json:"dkim_domain,omitempty"`
		DKIMSelector string `json:"dkim_selector,omitempty"`
		IP           string `json:"ip,omitempty"`
	} `json:"used"`
}

type SPFFlattenInfo struct {
	Networks         []SPFNetwork `json:"networks,omitempty"`
	LookupCount      int          `json:"lookup_count"`
	LimitReached     bool         `json:"limit_reached"`
	UnsupportedTerms []string     `json:"unsupported_terms,omitempty"`
	Errors           []string     `json:"errors,omitempty"`
}

type JSONResult struct {
	Timestamp      string             `json:"timestamp"`
	Domain         string             `json:"domain"`
	SPFRecords     []string           `json:"spf_records,omitempty"`
	SPFFlatten     *SPFFlattenInfo    `json:"spf_flatten,omitempty"`
	SPFCheck       *JSONSPFCheck      `json:"spf_check,omitempty"`
	DKIMDNS        *DKIMRecord        `json:"dkim_dns,omitempty"`
	DKIMSignatures []JSONDKIMSignature `json:"dkim_signatures,omitempty"`
	DMARC          *JSONDMARC         `json:"dmarc,omitempty"`
	Alignment      *JSONAlignment     `json:"alignment,omitempty"`
	DMARCResult    *JSONDMARCResult   `json:"dmarc_result,omitempty"`
	EmailAutofill  *JSONAutofill      `json:"email_autofill,omitempty"`
	Errors         []string           `json:"errors,omitempty"`
}

// ============================================================
// Utils
// ============================================================

var ipAnyRe = regexp.MustCompile(`(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-fA-F:]{3,39})`)

func lookupTXT(name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(context.Background(), name)
}

func lookupAandAAAA(name string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(context.Background(), "ip", name)
}

func lookupMXHosts(name string) ([]*net.MX, error) {
	return net.DefaultResolver.LookupMX(context.Background(), name)
}

func parseTagList(s string) map[string]string {
	m := make(map[string]string)
	for _, p := range strings.Split(s, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		m[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
	}
	return m
}

func domainFromAddr(addr string) (string, error) {
	if strings.Contains(addr, "<") && strings.Contains(addr, ">") {
		start := strings.Index(addr, "<")
		end := strings.LastIndex(addr, ">")
		if start >= 0 && end > start {
			addr = addr[start+1 : end]
		}
	}
	i := strings.LastIndex(addr, "@")
	if i < 0 || i == len(addr)-1 {
		return "", fmt.Errorf("adresse invalide: %q", addr)
	}
	return strings.ToLower(addr[i+1:]), nil
}

func orgDomain(d string) string {
	parts := strings.Split(strings.ToLower(d), ".")
	if len(parts) <= 2 {
		return strings.ToLower(d)
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func isSubdomain(sub, parent string) bool {
	sub = strings.ToLower(sub)
	parent = strings.ToLower(parent)
	if sub == parent {
		return false
	}
	return strings.HasSuffix(sub, "."+parent)
}

func aligned(fromDomain, otherDomain, mode string) bool {
	fromDomain = strings.ToLower(fromDomain)
	otherDomain = strings.ToLower(otherDomain)
	if otherDomain == "" {
		return false
	}
	if mode == "s" {
		return fromDomain == otherDomain
	}
	return orgDomain(fromDomain) == orgDomain(otherDomain)
}

// ============================================================
// DMARC — parser stdlib pur (RFC 7489)
// ============================================================

func parseDMARCRecord(raw string) (DMARCRecord, error) {
	rec := DMARCRecord{
		Percentage:    100,
		SPFAlignment:  "r",
		DKIMAlignment: "r",
	}
	tags := parseTagList(raw)

	v, ok := tags["v"]
	if !ok || !strings.EqualFold(v, "DMARC1") {
		return rec, fmt.Errorf("tag v=DMARC1 manquant ou invalide")
	}

	if p, ok := tags["p"]; ok {
		switch strings.ToLower(p) {
		case "none", "quarantine", "reject":
			rec.Policy = strings.ToLower(p)
		default:
			return rec, fmt.Errorf("valeur p= invalide: %q", p)
		}
	} else {
		return rec, fmt.Errorf("tag p= obligatoire manquant")
	}

	if sp, ok := tags["sp"]; ok {
		switch strings.ToLower(sp) {
		case "none", "quarantine", "reject":
			rec.SubdomainPolicy = strings.ToLower(sp)
		}
	}

	if aspf, ok := tags["aspf"]; ok {
		switch strings.ToLower(aspf) {
		case "r", "s":
			rec.SPFAlignment = strings.ToLower(aspf)
		}
	}

	if adkim, ok := tags["adkim"]; ok {
		switch strings.ToLower(adkim) {
		case "r", "s":
			rec.DKIMAlignment = strings.ToLower(adkim)
		}
	}

	if pct, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(pct)); err == nil && n >= 0 && n <= 100 {
			rec.Percentage = n
		}
	}

	if rua, ok := tags["rua"]; ok {
		for _, u := range strings.Split(rua, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				rec.RUA = append(rec.RUA, u)
			}
		}
	}

	if ruf, ok := tags["ruf"]; ok {
		for _, u := range strings.Split(ruf, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				rec.RUF = append(rec.RUF, u)
			}
		}
	}

	return rec, nil
}

// ============================================================
// SPF — lookup brut
// ============================================================

func findSPFRecords(domain string) (*SPFRecord, error) {
	txts, err := lookupTXT(domain)
	if err != nil {
		return nil, err
	}
	var spfTxts []string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			spfTxts = append(spfTxts, t)
		}
	}
	if len(spfTxts) == 0 {
		return nil, fmt.Errorf("aucun enregistrement SPF trouvé")
	}
	return &SPFRecord{Raw: spfTxts}, nil
}

// ============================================================
// SPF — check IP/MFROM (lib blitiri)
// ============================================================

func checkSPF(ip net.IP, mailFrom, helo string) (spf.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := spf.CheckHostWithSender(ctx, ip, helo, mailFrom, nil)
	return res, err
}

// ============================================================
// SPF — flatten complet avec comptage de lookups
// ============================================================

const spfMaxLookups = 10

type spfFlattenCtx struct {
	visited          map[string]bool
	nets             []SPFNetwork
	lookupCount      int
	limitReached     bool
	unsupportedTerms []string
	errs             []string
	permissive       bool
}

func newSPFFlattenCtx(permissive bool) *spfFlattenCtx {
	return &spfFlattenCtx{
		visited:    make(map[string]bool),
		permissive: permissive,
	}
}

func (c *spfFlattenCtx) addErr(e string) {
	if !c.permissive {
		c.errs = append(c.errs, e)
	}
}

func (c *spfFlattenCtx) consumeLookup() bool {
	if c.limitReached {
		return false
	}
	c.lookupCount++
	if c.lookupCount > spfMaxLookups {
		c.limitReached = true
		c.errs = append(c.errs, fmt.Sprintf("limite de %d lookups DNS atteinte (RFC 7208 §4.6.4)", spfMaxLookups))
		return false
	}
	return true
}

func (c *spfFlattenCtx) flattenDomain(domain, source string) {
	domain = strings.ToLower(domain)
	if c.visited[domain] || c.limitReached {
		return
	}
	c.visited[domain] = true

	if !c.consumeLookup() {
		return
	}

	rec, err := findSPFRecords(domain)
	if err != nil {
		c.addErr(fmt.Sprintf("lookup SPF %s: %v", domain, err))
		return
	}

	for _, raw := range rec.Raw {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		for _, term := range fields[1:] {
			term = strings.TrimSpace(term)
			if term == "" {
				continue
			}
			switch term[0] {
			case '+', '-', '~', '?':
				if len(term) == 1 {
					continue
				}
				term = term[1:]
			}

			switch {
			case strings.HasPrefix(term, "include:"):
				if !c.limitReached {
					c.flattenDomain(strings.TrimPrefix(term, "include:"), domain)
				}
			case strings.HasPrefix(term, "redirect="):
				if !c.limitReached {
					c.flattenDomain(strings.TrimPrefix(term, "redirect="), domain)
				}
			case strings.HasPrefix(term, "ip4:"):
				c.nets = append(c.nets, SPFNetwork{CIDR: strings.TrimPrefix(term, "ip4:"), Source: domain})
			case strings.HasPrefix(term, "ip6:"):
				c.nets = append(c.nets, SPFNetwork{CIDR: strings.TrimPrefix(term, "ip6:"), Source: domain})
			case term == "a" || strings.HasPrefix(term, "a:") || strings.HasPrefix(term, "a/"):
				if !c.consumeLookup() {
					break
				}
				host := domain
				if strings.HasPrefix(term, "a:") {
					host = strings.TrimPrefix(term, "a:")
				}
				ips, err := lookupAandAAAA(host)
				if err != nil {
					c.addErr(fmt.Sprintf("lookup A %s: %v", host, err))
					break
				}
				for _, ip := range ips {
					if ip.To4() != nil {
						c.nets = append(c.nets, SPFNetwork{CIDR: ip.String() + "/32", Source: host})
					} else {
						c.nets = append(c.nets, SPFNetwork{CIDR: ip.String() + "/128", Source: host})
					}
				}
			case term == "mx" || strings.HasPrefix(term, "mx:") || strings.HasPrefix(term, "mx/"):
				if !c.consumeLookup() {
					break
				}
				host := domain
				if strings.HasPrefix(term, "mx:") {
					host = strings.TrimPrefix(term, "mx:")
				}
				mxs, err := lookupMXHosts(host)
				if err != nil {
					c.addErr(fmt.Sprintf("lookup MX %s: %v", host, err))
					break
				}
				for _, mx := range mxs {
					if !c.consumeLookup() {
						break
					}
					ips, err := lookupAandAAAA(mx.Host)
					if err != nil {
						c.addErr(fmt.Sprintf("lookup A MX %s: %v", mx.Host, err))
						continue
					}
					for _, ip := range ips {
						if ip.To4() != nil {
							c.nets = append(c.nets, SPFNetwork{CIDR: ip.String() + "/32", Source: mx.Host})
						} else {
							c.nets = append(c.nets, SPFNetwork{CIDR: ip.String() + "/128", Source: mx.Host})
						}
					}
				}
			case term == "all" || term == "+all" || term == "-all" || term == "~all" || term == "?all":
				// terminateur
			case strings.HasPrefix(term, "exists:") || strings.HasPrefix(term, "ptr") || strings.Contains(term, "%{"):
				c.unsupportedTerms = append(c.unsupportedTerms, term)
			default:
				c.unsupportedTerms = append(c.unsupportedTerms, term)
			}
		}
	}
}

func flattenSPF(domain string, permissive bool) *SPFFlattenInfo {
	ctx := newSPFFlattenCtx(permissive)
	ctx.flattenDomain(domain, domain)
	return &SPFFlattenInfo{
		Networks:         ctx.nets,
		LookupCount:      ctx.lookupCount,
		LimitReached:     ctx.limitReached,
		UnsupportedTerms: ctx.unsupportedTerms,
		Errors:           ctx.errs,
	}
}

// ============================================================
// DKIM — lookup clé publique DNS
// ============================================================

func findDKIMRecord(domain, selector string) (*DKIMRecord, error) {
	if selector == "" {
		return nil, fmt.Errorf("sélecteur DKIM non fourni")
	}
	name := selector + "._domainkey." + domain
	txts, err := lookupTXT(name)
	if err != nil {
		return nil, err
	}
	var dkimTxt string
	for _, t := range txts {
		if strings.Contains(strings.ToLower(t), "v=dkim1") {
			dkimTxt = t
			break
		}
	}
	if dkimTxt == "" {
		return nil, fmt.Errorf("aucun enregistrement DKIM v=DKIM1 trouvé pour %s", name)
	}
	return &DKIMRecord{
		Raw:  dkimTxt,
		Tags: parseTagList(dkimTxt),
	}, nil
}

// ============================================================
// DKIM — vérification signature email
// ============================================================

func verifyDKIMMessage(r io.Reader) ([]*dkim.Verification, error) {
	return dkim.Verify(r)
}

// ============================================================
// DMARC — lookup + parse
// ============================================================

func findDMARC(domain string) (*DMARCInfo, error) {
	name := "_dmarc." + domain
	txts, err := lookupTXT(name)
	if err != nil {
		return nil, err
	}
	var dmarcTxt string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(t)), "V=DMARC1") {
			dmarcTxt = strings.TrimSpace(t)
			break
		}
	}
	if dmarcTxt == "" {
		return nil, fmt.Errorf("aucun enregistrement DMARC trouvé")
	}
	rec, err := parseDMARCRecord(dmarcTxt)
	if err != nil {
		return nil, fmt.Errorf("erreur de parse DMARC: %w", err)
	}
	return &DMARCInfo{Raw: dmarcTxt, Record: rec}, nil
}

// ============================================================
// Extraction depuis un email brut (autofill)
// ============================================================

func extractFromEmail(raw []byte) (*EmailExtract, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	h := msg.Header
	res := &EmailExtract{}

	if from := h.Get("From"); from != "" {
		res.HeaderFrom = from
	}
	if rp := h.Get("Return-Path"); rp != "" {
		res.MailFrom = strings.Trim(rp, " <>")
	}

	if sigs, ok := h["Dkim-Signature"]; ok && len(sigs) > 0 {
		for _, p := range strings.Split(sigs[0], ";") {
			kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(kv[0])) {
			case "d":
				res.DKIMDomain = strings.TrimSpace(kv[1])
			case "s":
				res.DKIMSelector = strings.TrimSpace(kv[1])
			}
		}
	}

	recvs := h["Received"]
	for i := len(recvs) - 1; i >= 0; i-- {
		for _, ipStr := range ipAnyRe.FindAllString(recvs[i], -1) {
			ip := net.ParseIP(ipStr)
			if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
				continue
			}
			res.ClientIPs = append(res.ClientIPs, ip.String())
		}
		if len(res.ClientIPs) > 0 {
			break
		}
	}
	return res, nil
}

// ============================================================
// Calcul alignement + résumé DMARC
// ============================================================

func buildAlignment(fromDomain, mailFromDomain, dkimDomain string, dm *DMARCInfo) *JSONAlignment {
	return &JSONAlignment{
		FromDomain:     fromDomain,
		MailFromDomain: mailFromDomain,
		DKIMDomain:     dkimDomain,
		ASPF:           dm.Record.SPFAlignment,
		ADKIM:          dm.Record.DKIMAlignment,
		SPFAligned:     aligned(fromDomain, mailFromDomain, dm.Record.SPFAlignment),
		DKIMAligned:    aligned(fromDomain, dkimDomain, dm.Record.DKIMAlignment),
	}
}

func buildDMARCResult(dm *DMARCInfo, align *JSONAlignment, spfCheck *JSONSPFCheck, dkimSigs []JSONDKIMSignature, fromDomain string) *JSONDMARCResult {
	res := &JSONDMARCResult{}
	if dm == nil || align == nil {
		res.Reason = "DMARC ou alignement indisponible"
		return res
	}
	res.Evaluated = true
	res.Pct = dm.Record.Percentage
	if res.Pct == 0 {
		res.Pct = 100
	}

	if spfCheck != nil {
		res.SPFPass = (spfCheck.Result == "pass")
	}
	for _, s := range dkimSigs {
		if s.Valid {
			res.DKIMPass = true
			break
		}
	}

	res.SPFAligned = align.SPFAligned
	res.DKIMAligned = align.DKIMAligned
	spfOk := res.SPFPass && res.SPFAligned
	dkimOk := res.DKIMPass && res.DKIMAligned
	res.Pass = spfOk || dkimOk

	switch {
	case res.Pass && spfOk && dkimOk:
		res.Reason = "SPF et DKIM passent et sont alignés"
	case res.Pass && spfOk:
		res.Reason = "SPF passe et est aligné (DKIM ignoré ou non aligné)"
	case res.Pass && dkimOk:
		res.Reason = "DKIM passe et est aligné (SPF ignoré ou non aligné)"
	default:
		res.Reason = "Ni SPF ni DKIM ne passent avec alignement DMARC"
	}

	policy := dm.Record.Policy
	if policy == "" {
		policy = "none"
	}
	res.Policy = policy

	effective := policy
	if dm.Record.SubdomainPolicy != "" && isSubdomain(fromDomain, orgDomain(fromDomain)) {
		effective = dm.Record.SubdomainPolicy
	}
	res.EffectivePolicy = effective

	if res.Pass {
		res.Action = "none"
	} else {
		switch effective {
		case "reject":
			res.Action = "reject"
		case "quarantine":
			res.Action = "quarantine"
		default:
			res.Action = "none (monitor)"
		}
	}
	return res
}

// ============================================================
// Affichage texte humain
// ============================================================

func printSPF(spfRec *SPFRecord) {
	fmt.Println("=== SPF ===")
	for i, r := range spfRec.Raw {
		fmt.Printf("Record %d : %s\n", i+1, r)
	}
}

func printSPFFlatten(info *SPFFlattenInfo) {
	fmt.Println("=== SPF Flatten ===")
	fmt.Printf("Lookups DNS effectués : %d/%d\n", info.LookupCount, spfMaxLookups)
	if info.LimitReached {
		fmt.Println("ATTENTION : limite de lookups RFC atteinte, résultat partiel")
	}
	if len(info.Networks) == 0 {
		fmt.Println("Aucun réseau collecté.")
	} else {
		for _, n := range info.Networks {
			fmt.Printf("  %s (via %s)\n", n.CIDR, n.Source)
		}
	}
	if len(info.UnsupportedTerms) > 0 {
		fmt.Printf("Termes non résolus (exists/ptr/macro) : %s\n", strings.Join(info.UnsupportedTerms, ", "))
	}
	for _, e := range info.Errors {
		fmt.Printf("  ERREUR: %s\n", e)
	}
}

func printDKIM(dk *DKIMRecord) {
	fmt.Println("=== DKIM ===")
	fmt.Printf("Brut : %s\n", dk.Raw)
	fmt.Println("Tags :")
	for k, v := range dk.Tags {
		fmt.Printf("  %s = %s\n", k, v)
	}
}

func printDKIMVerifications(vs []*dkim.Verification) {
	fmt.Println("=== DKIM Verify ===")
	if len(vs) == 0 {
		fmt.Println("Aucune signature DKIM trouvée.")
		return
	}
	for i, v := range vs {
		status := "INVALID"
		if v.Err == nil {
			status = "VALID"
		}
		fmt.Printf("Signature %d: %s (d=%s, s=%s, err=%v)\n", i+1, status, v.Domain, v.Selector, v.Err)
	}
}

func printDMARC(info *DMARCInfo) {
	fmt.Println("=== DMARC ===")
	fmt.Printf("Brut              : %s\n", info.Raw)
	fmt.Printf("Politique p       : %s\n", info.Record.Policy)
	if info.Record.SubdomainPolicy != "" {
		fmt.Printf("Politique sp      : %s\n", info.Record.SubdomainPolicy)
	}
	fmt.Printf("Alignement aspf   : %s\n", info.Record.SPFAlignment)
	fmt.Printf("Alignement adkim  : %s\n", info.Record.DKIMAlignment)
	fmt.Printf("Pourcentage pct   : %d\n", info.Record.Percentage)
	fmt.Printf("rua               : %v\n", info.Record.RUA)
	fmt.Printf("ruf               : %v\n", info.Record.RUF)
}

func printAlignment(align *JSONAlignment) {
	fmt.Println("=== Alignement DMARC ===")
	fmt.Printf("Domaine From        : %s\n", align.FromDomain)
	fmt.Printf("Domaine MAIL FROM   : %s\n", align.MailFromDomain)
	fmt.Printf("Domaine DKIM (d=)   : %s\n", align.DKIMDomain)
	fmt.Printf("aspf (SPF align)    : %s\n", align.ASPF)
	fmt.Printf("adkim (DKIM align)  : %s\n", align.ADKIM)
	fmt.Printf("SPF aligné          : %v\n", align.SPFAligned)
	fmt.Printf("DKIM aligné         : %v\n", align.DKIMAligned)
}

func printDMARCResult(r *JSONDMARCResult) {
	if r == nil {
		return
	}
	fmt.Println("=== DMARC Résumé ===")
	if !r.Evaluated {
		fmt.Printf("DMARC non évalué: %s\n", r.Reason)
		return
	}
	pass := "FAIL"
	if r.Pass {
		pass = "PASS"
	}
	fmt.Printf("DMARC global      : %s\n", pass)
	fmt.Printf("SPF pass          : %v (aligné: %v)\n", r.SPFPass, r.SPFAligned)
	fmt.Printf("DKIM pass         : %v (aligné: %v)\n", r.DKIMPass, r.DKIMAligned)
	fmt.Printf("Politique p       : %s\n", r.Policy)
	fmt.Printf("Pourcentage pct   : %d%%\n", r.Pct)
	if r.EffectivePolicy != "" && r.EffectivePolicy != r.Policy {
		fmt.Printf("Politique effective: %s (sp=)\n", r.EffectivePolicy)
	}
	fmt.Printf("Action théorique  : %s\n", r.Action)
	fmt.Printf("Raison            : %s\n", r.Reason)
}

// ============================================================
// main
// ============================================================

func main() {
	domain := flag.String("domain", "", "domaine à analyser (obligatoire)")
	dkimSelector := flag.String("dkim-selector", "", "sélecteur DKIM (optionnel, pour lookup DNS)")
	dkimD := flag.String("dkim-d", "", "domaine DKIM (paramètre d= de la signature, pour l'alignement)")
	ipStr := flag.String("ip", "", "IP source à tester pour SPF")
	mailFrom := flag.String("mailfrom", "", "adresse MAIL FROM (ex: bounce@example.com)")
	headerFrom := flag.String("from", "", "adresse From: pour l'alignement DMARC")
	helo := flag.String("helo", "localhost", "nom HELO/EHLO pour SPF")
	emailFile := flag.String("email", "", "chemin vers un email brut .eml pour vérification DKIM")
	autofill := flag.Bool("autofill-from-email", false, "extraire From/MAIL FROM/DKIM depuis -email")
	doFlatten := flag.Bool("flatten", false, "résoudre toutes les IP autorisées par SPF")
	jsonOut := flag.Bool("json", false, "sortie JSON human-readable")
	jsonlOut := flag.Bool("jsonl", false, "sortie JSON one-liner (SIEM/Loki/Elastic)")
	permissive := flag.Bool("permissive", false, "mode permissif: ignore les erreurs DNS non critiques")

	flag.Parse()

	if *domain == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -domain example.com [options]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	result := JSONResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Domain:    *domain,
	}
	var jsonErrors []string
	var emailRaw []byte

	if *emailFile != "" {
		f, err := os.Open(*emailFile)
		if err != nil {
			if !*permissive {
				log.Printf("Impossible d'ouvrir %s: %v\n", *emailFile, err)
			}
			jsonErrors = append(jsonErrors, fmt.Sprintf("open email: %v", err))
		} else {
			defer f.Close()
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, f); err != nil {
				jsonErrors = append(jsonErrors, fmt.Sprintf("read email: %v", err))
			} else {
				emailRaw = buf.Bytes()
			}
		}
	}

	var emailExtract *EmailExtract
	if *autofill && len(emailRaw) > 0 {
		if ext, err := extractFromEmail(emailRaw); err != nil {
			jsonErrors = append(jsonErrors, fmt.Sprintf("autofill: %v", err))
		} else {
			emailExtract = ext
			if *headerFrom == "" {
				*headerFrom = ext.HeaderFrom
			}
			if *mailFrom == "" {
				*mailFrom = ext.MailFrom
			}
			if *dkimD == "" {
				*dkimD = ext.DKIMDomain
			}
			if *dkimSelector == "" {
				*dkimSelector = ext.DKIMSelector
			}
			if *ipStr == "" && len(ext.ClientIPs) > 0 {
				*ipStr = ext.ClientIPs[0]
			}
		}
	}

	isJSON := *jsonOut || *jsonlOut

	if s, err := findSPFRecords(*domain); err != nil {
		jsonErrors = append(jsonErrors, fmt.Sprintf("SPF: %v", err))
		if !isJSON {
			fmt.Println("=== SPF ===")
			fmt.Printf("Erreur SPF: %v\n\n", err)
		}
	} else {
		result.SPFRecords = s.Raw
		if !isJSON {
			printSPF(s)
			fmt.Println()
		}
	}

	if *doFlatten {
		info := flattenSPF(*domain, *permissive)
		result.SPFFlatten = info
		if !isJSON {
			printSPFFlatten(info)
			fmt.Println()
		}
	}

	if *dkimSelector != "" {
		if dk, err := findDKIMRecord(*domain, *dkimSelector); err != nil {
			jsonErrors = append(jsonErrors, fmt.Sprintf("DKIM DNS: %v", err))
			if !isJSON {
				fmt.Println("=== DKIM ===")
				fmt.Printf("Erreur DKIM: %v\n\n", err)
			}
		} else {
			result.DKIMDNS = dk
			if !isJSON {
				printDKIM(dk)
				fmt.Println()
			}
		}
	} else if !isJSON {
		fmt.Println("=== DKIM ===")
		fmt.Println("Sélecteur DKIM non fourni, saut du lookup DKIM DNS.")
		fmt.Println()
	}

	var dmarcInfo *DMARCInfo
	if dm, err := findDMARC(*domain); err != nil {
		jsonErrors = append(jsonErrors, fmt.Sprintf("DMARC: %v", err))
		if !isJSON {
			fmt.Println("=== DMARC ===")
			fmt.Printf("Erreur DMARC: %v\n\n", err)
		}
	} else {
		dmarcInfo = dm
		pct := dm.Record.Percentage
		if pct == 0 {
			pct = 100
		}
		result.DMARC = &JSONDMARC{
			Raw:             dm.Raw,
			Policy:          dm.Record.Policy,
			SubdomainPolicy: dm.Record.SubdomainPolicy,
			ASPF:            dm.Record.SPFAlignment,
			ADKIM:           dm.Record.DKIMAlignment,
			RUA:             dm.Record.RUA,
			RUF:             dm.Record.RUF,
			Pct:             pct,
		}
		if !isJSON {
			printDMARC(dm)
			fmt.Println()
		}
	}

	if *ipStr != "" && *mailFrom != "" {
		ip := net.ParseIP(*ipStr)
		if ip == nil {
			jsonErrors = append(jsonErrors, fmt.Sprintf("IP invalide: %s", *ipStr))
		} else {
			res, err := checkSPF(ip, *mailFrom, *helo)
			jc := &JSONSPFCheck{
				IP:       ip.String(),
				MailFrom: *mailFrom,
				Helo:     *helo,
			}
			if err != nil && !*permissive {
				jc.Error = err.Error()
			} else {
				jc.Result = string(res)
			}
			result.SPFCheck = jc
			if !isJSON {
				fmt.Println("=== SPF Check ===")
				if err != nil && !*permissive {
					fmt.Printf("Erreur SPF pour IP=%s, MAIL FROM=%s: %v\n", ip.String(), *mailFrom, err)
				} else {
					fmt.Printf("Résultat SPF pour IP=%s, MAIL FROM=%s: %s\n", ip.String(), *mailFrom, res)
				}
				fmt.Println()
			}
		}
	} else if (*ipStr != "" || *mailFrom != "") && !isJSON {
		fmt.Println("=== SPF Check ===")
		fmt.Println("Pour tester SPF, il faut à la fois -ip et -mailfrom.")
		fmt.Println()
	}

	if len(emailRaw) > 0 {
		verifs, err := verifyDKIMMessage(bytes.NewReader(emailRaw))
		if err != nil && !*permissive {
			jsonErrors = append(jsonErrors, fmt.Sprintf("DKIM Verify: %v", err))
			if !isJSON {
				fmt.Println("=== DKIM Verify ===")
				fmt.Printf("Erreur DKIM: %v\n\n", err)
			}
		} else {
			var sigs []JSONDKIMSignature
			for _, v := range verifs {
				s := JSONDKIMSignature{
					Domain:   v.Domain,
					Selector: v.Selector,
					Valid:    v.Err == nil,
				}
				if v.Err != nil {
					s.Error = v.Err.Error()
				}
				sigs = append(sigs, s)
			}
			result.DKIMSignatures = sigs
			if !isJSON {
				printDKIMVerifications(verifs)
				fmt.Println()
			}
			if *dkimD == "" {
				for _, v := range verifs {
					if v.Err == nil {
						*dkimD = v.Domain
						break
					}
				}
			}
		}
	}

	if dmarcInfo != nil && *headerFrom != "" {
		fromDomain, err := domainFromAddr(*headerFrom)
		if err != nil {
			jsonErrors = append(jsonErrors, fmt.Sprintf("Alignement: %v", err))
		} else {
			mfDomain := *domain
			if *mailFrom != "" {
				if d, err := domainFromAddr(*mailFrom); err == nil {
					mfDomain = d
				}
			}
			dkimDomain := *dkimD
			if dkimDomain == "" {
				dkimDomain = *domain
			}
			align := buildAlignment(fromDomain, mfDomain, dkimDomain, dmarcInfo)
			result.Alignment = align
			if !isJSON {
				printAlignment(align)
				fmt.Println()
			}
			dmarcRes := buildDMARCResult(dmarcInfo, align, result.SPFCheck, result.DKIMSignatures, fromDomain)
			result.DMARCResult = dmarcRes
			if !isJSON {
				printDMARCResult(dmarcRes)
			}
		}
	} else if dmarcInfo != nil && !isJSON {
		fmt.Println("=== Alignement DMARC ===")
		fmt.Println("Fournis -from (et optionnellement -mailfrom, -dkim-d, ou -email -autofill-from-email).")
	}

	if isJSON {
		result.Errors = jsonErrors
		if *autofill {
			af := &JSONAutofill{Enabled: true, FromEmail: emailExtract}
			if emailExtract != nil {
				af.Used.HeaderFrom = *headerFrom
				af.Used.MailFrom = *mailFrom
				af.Used.DKIMDomain = *dkimD
				af.Used.DKIMSelector = *dkimSelector
				af.Used.IP = *ipStr
			}
			result.EmailAutofill = af
		}
		enc := json.NewEncoder(os.Stdout)
		if !*jsonlOut {
			enc.SetIndent("", "  ")
		}
		if err := enc.Encode(result); err != nil {
			log.Fatalf("Erreur encodage JSON: %v", err)
		}
	}
}
