package varlink

import (
	"context"
	"encoding/json"
	"log"

	"github.com/foxboron/attezt/internal/inventory"
	"github.com/foxboron/attezt/internal/varlink/devattezt"
)

type VarlinkHost struct {
	devattezt.VarlinkInterface
	inventory inventory.Inventory
}

func New(backend inventory.Inventory) *devattezt.VarlinkInterface {
	host := VarlinkHost{inventory: backend}
	return devattezt.VarlinkNew(&host)
}

func (v *VarlinkHost) GetDevice(ctx context.Context, c devattezt.VarlinkCall, ekcert string) error {
	log.Println("called getdevice")
	var ret devattezt.Device
	devices, err := v.inventory.GetEntry(ekcert)
	if err != nil {
		return c.ReplyError(ctx, "dev.attezt.Error", nil)
	}
	b, err := json.Marshal(devices)
	if err != nil {
		return c.ReplyError(ctx, "dev.attezt.Error", nil)
	}
	if err := json.Unmarshal(b, &ret); err != nil {
		return c.ReplyError(ctx, "dev.attezt.Error", nil)
	}
	return c.ReplyGetDevice(ctx, ret)
}

func (v *VarlinkHost) ListDevices(ctx context.Context, c devattezt.VarlinkCall) error {
	log.Println("called listdevices")
	var ret []devattezt.Device
	devices, err := v.inventory.List()
	if err != nil {
		return c.ReplyError(ctx, "dev.attezt.Error", nil)
	}
	b, err := json.Marshal(devices)
	if err != nil {
		return c.ReplyError(ctx, "dev.attezt.Error", nil)
	}
	if err := json.Unmarshal(b, &ret); err != nil {
		return c.ReplyError(ctx, "dev.attezt.Error", nil)
	}
	return c.ReplyListDevices(ctx, ret)
}

func (v *VarlinkHost) Enroll(ctx context.Context, c devattezt.VarlinkCall, ekcert string) error {
	log.Println("called enroll")
	if err := v.inventory.Enroll(map[string]any{
		"ekcert": ekcert,
	}); err != nil {
		return c.ReplyError(ctx, "dev.attezt.Error", nil)
	}
	return c.ReplyEnroll(ctx)
}

func (v *VarlinkHost) Remove(ctx context.Context, c devattezt.VarlinkCall, ekcert string) error {
	log.Println("called remove")
	if err := v.inventory.Remove(map[string]any{
		"ekcert": ekcert,
	}); err != nil {
		return c.ReplyError(ctx, "dev.attezt.Error", nil)
	}
	return c.ReplyRemove(ctx)
}
