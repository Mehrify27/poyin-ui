package job

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	ldaputil "github.com/mhsanaei/3x-ui/v2/util/ldap"
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/google/uuid"
)

var DefaultTruthyValues = []string{"true", "1", "yes", "on"}

type LdapSyncJob struct {
	settingService service.SettingService
	inboundService service.InboundService
	xrayService    service.XrayService
}

func getSettingStringOr(fn func() (string, error), fallback string) string {
	v, err := fn()
	if err != nil {
		logger.Warning("LDAP setting string read failed:", err)
		return fallback
	}
	if v == "" {
		return fallback
	}
	return v
}

func getSettingIntOr(fn func() (int, error), fallback int) int {
	v, err := fn()
	if err != nil {
		logger.Warning("LDAP setting int read failed:", err)
		return fallback
	}
	return v
}

func getSettingBoolOr(fn func() (bool, error), fallback bool) bool {
	v, err := fn()
	if err != nil {
		logger.Warning("LDAP setting bool read failed:", err)
		return fallback
	}
	return v
}

func NewLdapSyncJob() *LdapSyncJob {
	return new(LdapSyncJob)
}

func (j *LdapSyncJob) Run() {
	logger.Info("LDAP sync job started")

	enabled, err := j.settingService.GetLdapEnable()
	if err != nil || !enabled {
		logger.Warning("LDAP disabled or failed to fetch flag")
		return
	}

	host, err := j.settingService.GetLdapHost()
	if err != nil || strings.TrimSpace(host) == "" {
		logger.Warning("LDAP sync skipped: invalid or missing ldapHost:", err)
		return
	}
	port, err := j.settingService.GetLdapPort()
	if err != nil || port <= 0 {
		logger.Warning("LDAP sync skipped: invalid or missing ldapPort:", err)
		return
	}
	baseDN, err := j.settingService.GetLdapBaseDN()
	if err != nil || strings.TrimSpace(baseDN) == "" {
		logger.Warning("LDAP sync skipped: invalid or missing ldapBaseDN:", err)
		return
	}

	// --- LDAP fetch ---
	flagField := getSettingStringOr(j.settingService.GetLdapFlagField, getSettingStringOr(j.settingService.GetLdapVlessField, ""))
	cfg := ldaputil.Config{
		Host:       host,
		Port:       port,
		UseTLS:     getSettingBoolOr(j.settingService.GetLdapUseTLS, false),
		BindDN:     getSettingStringOr(j.settingService.GetLdapBindDN, ""),
		Password:   getSettingStringOr(j.settingService.GetLdapPassword, ""),
		BaseDN:     baseDN,
		UserFilter: getSettingStringOr(j.settingService.GetLdapUserFilter, ""),
		UserAttr:   getSettingStringOr(j.settingService.GetLdapUserAttr, ""),
		FlagField:  flagField,
		TruthyVals: splitCsv(getSettingStringOr(j.settingService.GetLdapTruthyValues, "")),
		Invert:     getSettingBoolOr(j.settingService.GetLdapInvertFlag, false),
	}

	flags, err := ldaputil.FetchVlessFlags(cfg)
	if err != nil {
		logger.Warning("LDAP fetch failed:", err)
		return
	}
	logger.Infof("Fetched %d LDAP flags", len(flags))

	// --- Load all inbounds and all clients once ---
	inboundTags := splitCsv(getSettingStringOr(j.settingService.GetLdapInboundTags, ""))
	inbounds, err := j.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("Failed to get inbounds:", err)
		return
	}

	allClients := map[string]*model.Client{}  // email -> client
	inboundMap := map[string]*model.Inbound{} // tag -> inbound
	for _, ib := range inbounds {
		inboundMap[ib.Tag] = ib
		clients, _ := j.inboundService.GetClients(ib)
		for i := range clients {
			allClients[clients[i].Email] = &clients[i]
		}
	}

	// --- Prepare batch operations ---
	autoCreate := getSettingBoolOr(j.settingService.GetLdapAutoCreate, false)
	defGB := getSettingIntOr(j.settingService.GetLdapDefaultTotalGB, 0)
	defExpiryDays := getSettingIntOr(j.settingService.GetLdapDefaultExpiryDays, 0)
	defLimitIP := getSettingIntOr(j.settingService.GetLdapDefaultLimitIP, 0)

	clientsToCreate := map[string][]model.Client{} // tag -> []new clients
	clientsToEnable := map[string][]string{}       // tag -> []email
	clientsToDisable := map[string][]string{}      // tag -> []email

	for email, allowed := range flags {
		exists := allClients[email] != nil
		for _, tag := range inboundTags {
			ib := inboundMap[tag]
			if ib == nil {
				continue
			}
			if !exists && allowed && autoCreate {
				newClient := j.buildClient(ib, email, defGB, defExpiryDays, defLimitIP)
				clientsToCreate[tag] = append(clientsToCreate[tag], newClient)
			} else if exists {
				if allowed && !allClients[email].Enable {
					clientsToEnable[tag] = append(clientsToEnable[tag], email)
				} else if !allowed && allClients[email].Enable {
					clientsToDisable[tag] = append(clientsToDisable[tag], email)
				}
			}
		}
	}

	// --- Execute batch create ---
	for tag, newClients := range clientsToCreate {
		if len(newClients) == 0 {
			continue
		}
		ib := inboundMap[tag]
		if ib == nil {
			continue
		}
		payload := &model.Inbound{Id: ib.Id}
		payload.Settings = j.clientsToJSON(newClients)
		if _, err := j.inboundService.AddInboundClient(payload); err != nil {
			logger.Warningf("Failed to add clients for tag %s: %v", tag, err)
		} else {
			logger.Infof("LDAP auto-create: %d clients for %s", len(newClients), tag)
			j.xrayService.SetToNeedRestart()
		}
	}

	// --- Execute enable/disable batch ---
	for tag, emails := range clientsToEnable {
		if ib := inboundMap[tag]; ib != nil {
			j.batchSetEnable(ib, emails, true)
		}
	}
	for tag, emails := range clientsToDisable {
		if ib := inboundMap[tag]; ib != nil {
			j.batchSetEnable(ib, emails, false)
		}
	}

	// --- Auto delete clients not in LDAP ---
	autoDelete := getSettingBoolOr(j.settingService.GetLdapAutoDelete, false)
	if autoDelete {
		ldapEmailSet := map[string]struct{}{}
		for e := range flags {
			ldapEmailSet[e] = struct{}{}
		}
		for _, tag := range inboundTags {
			j.deleteClientsNotInLDAP(tag, ldapEmailSet)
		}
	}
}

func splitCsv(s string) []string {
	if s == "" {
		return DefaultTruthyValues
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// buildClient creates a new client for auto-create
func (j *LdapSyncJob) buildClient(ib *model.Inbound, email string, defGB, defExpiryDays, defLimitIP int) model.Client {
	c := model.Client{
		Email:   email,
		Enable:  true,
		LimitIP: defLimitIP,
		TotalGB: int64(defGB),
	}
	if defExpiryDays > 0 {
		c.ExpiryTime = time.Now().Add(time.Duration(defExpiryDays) * 24 * time.Hour).UnixMilli()
	}
	if ib == nil {
		c.ID = uuid.NewString()
		return c
	}
	switch ib.Protocol {
	case model.Trojan, model.Shadowsocks:
		c.Password = uuid.NewString()
	default:
		c.ID = uuid.NewString()
	}
	return c
}

// batchSetEnable enables/disables clients in batch through a single call
func (j *LdapSyncJob) batchSetEnable(ib *model.Inbound, emails []string, enable bool) {
	if len(emails) == 0 {
		return
	}

	// Prepare JSON for mass update
	clients := make([]model.Client, 0, len(emails))
	for _, email := range emails {
		clients = append(clients, model.Client{
			Email:  email,
			Enable: enable,
		})
	}

	payload := &model.Inbound{
		Id:       ib.Id,
		Settings: j.clientsToJSON(clients),
	}

	// Use a single AddInboundClient call to update enable
	if _, err := j.inboundService.AddInboundClient(payload); err != nil {
		logger.Warningf("Batch set enable failed for inbound %s: %v", ib.Tag, err)
		return
	}

	logger.Infof("Batch set enable=%v for %d clients in inbound %s", enable, len(emails), ib.Tag)
	j.xrayService.SetToNeedRestart()
}

// deleteClientsNotInLDAP deletes clients not in LDAP using batches and a single restart
func (j *LdapSyncJob) deleteClientsNotInLDAP(inboundTag string, ldapEmails map[string]struct{}) {
	inbounds, err := j.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("Failed to get inbounds for deletion:", err)
		return
	}

	batchSize := 50 //  clients in 1 batch
	restartNeeded := false

	for _, ib := range inbounds {
		if ib.Tag != inboundTag {
			continue
		}
		clients, err := j.inboundService.GetClients(ib)
		if err != nil {
			logger.Warningf("Failed to get clients for inbound %s: %v", ib.Tag, err)
			continue
		}

		// Collect clients for deletion
		toDelete := []model.Client{}
		for _, c := range clients {
			if _, ok := ldapEmails[c.Email]; !ok {
				toDelete = append(toDelete, c)
			}
		}

		if len(toDelete) == 0 {
			continue
		}

		// Delete in batches
		for i := 0; i < len(toDelete); i += batchSize {
			end := min(i+batchSize, len(toDelete))
			batch := toDelete[i:end]

			for _, c := range batch {
				var clientKey string
				switch ib.Protocol {
				case model.Trojan:
					clientKey = c.Password
				case model.Shadowsocks:
					clientKey = c.Email
				default: // vless/vmess
					clientKey = c.ID
				}

				if _, err := j.inboundService.DelInboundClient(ib.Id, clientKey); err != nil {
					logger.Warningf("Failed to delete client %s from inbound id=%d(tag=%s): %v",
						c.Email, ib.Id, ib.Tag, err)
				} else {
					logger.Infof("Deleted client %s from inbound id=%d(tag=%s)",
						c.Email, ib.Id, ib.Tag)
					// do not restart here
					restartNeeded = true
				}
			}
		}
	}

	// One time after all batches
	if restartNeeded {
		j.xrayService.SetToNeedRestart()
		logger.Info("Xray restart scheduled after batch deletion")
	}
}

// clientsToJSON serializes an array of clients safely using encoding/json.
func (j *LdapSyncJob) clientsToJSON(clients []model.Client) string {
	type ldapClientPayload struct {
		ID         string `json:"id,omitempty"`
		Password   string `json:"password,omitempty"`
		Email      string `json:"email"`
		Enable     bool   `json:"enable"`
		LimitIP    int    `json:"limitIp"`
		TotalGB    int64  `json:"totalGB"`
		ExpiryTime int64  `json:"expiryTime,omitempty"`
	}
	items := make([]ldapClientPayload, 0, len(clients))
	for _, c := range clients {
		items = append(items, ldapClientPayload{
			ID:         c.ID,
			Password:   c.Password,
			Email:      c.Email,
			Enable:     c.Enable,
			LimitIP:    c.LimitIP,
			TotalGB:    c.TotalGB,
			ExpiryTime: c.ExpiryTime,
		})
	}
	raw, err := json.Marshal(struct {
		Clients []ldapClientPayload `json:"clients"`
	}{Clients: items})
	if err != nil {
		return `{"clients":[]}`
	}
	return string(raw)
}
