package repository

import (
	"errors"

	"mikrotik-ppp-management/internal/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type OLTRepository struct {
	db *gorm.DB
}

func NewOLTRepository(db *gorm.DB) *OLTRepository {
	return &OLTRepository{db: db}
}

func (r *OLTRepository) AutoMigrate() error {
	return r.db.AutoMigrate(&model.OLT{}, &model.ONUDevice{})
}

func (r *OLTRepository) Create(olt *model.OLT) error {
	return r.db.Create(olt).Error
}

func (r *OLTRepository) List() ([]model.OLT, error) {
	var olts []model.OLT
	err := r.db.Order("id ASC").Find(&olts).Error
	return olts, err
}

func (r *OLTRepository) GetByID(id int) (*model.OLT, error) {
	var olt model.OLT
	if err := r.db.First(&olt, id).Error; err != nil {
		return nil, err
	}
	return &olt, nil
}

func (r *OLTRepository) Update(olt *model.OLT) error {
	return r.db.Model(&model.OLT{}).Where("id = ?", olt.ID).Updates(map[string]interface{}{
		"name":            olt.Name,
		"ip_address":      olt.IPAddress,
		"snmp_ro":         olt.SNMPRO,
		"snmp_rw":         olt.SNMPRW,
		"snmp_port":       olt.SNMPPort,
		"telnet_host":     olt.TelnetHost,
		"telnet_port":     olt.TelnetPort,
		"telnet_username": olt.TelnetUsername,
		"telnet_password": olt.TelnetPassword,
	}).Error
}

func (r *OLTRepository) Delete(id int) error {
	return r.db.Delete(&model.OLT{}, id).Error
}

func (r *OLTRepository) UpsertONUs(oltID int, onus []model.ONUDevice) error {
	if len(onus) == 0 {
		return nil
	}
	for i := range onus {
		onus[i].OLTID = oltID
	}
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "olt_id"}, {Name: "serial_number"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"onu_interface",
			"name",
			"onu_type",
			"description",
			"board_port",
			"status",
			"admin_state",
			"phase_state",
			"pppoe_username",
			"pppoe_password",
			"vlan",
			"rx_power",
			"tx_power",
			"last_online",
			"last_offline",
			"offline_reason",
			"last_seen",
		}),
	}).Create(&onus).Error
}

func (r *OLTRepository) ListONUs(oltID int) ([]model.ONUDevice, error) {
	var onus []model.ONUDevice
	err := r.db.Where("olt_id = ?", oltID).Order("board_port ASC, serial_number ASC").Find(&onus).Error
	return onus, err
}

func (r *OLTRepository) GetONUBySerial(sn string) (*model.ONUDevice, error) {
	var onu model.ONUDevice
	err := r.db.Preload("OLT").Where("serial_number = ?", sn).First(&onu).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	return &onu, err
}
