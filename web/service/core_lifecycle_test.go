package service

import (
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestCountEnabledInbounds(t *testing.T) {
	inbounds := []*model.Inbound{
		nil,
		{Id: 1, Enable: false},
		{Id: 2, Enable: false},
	}
	if got := countEnabledInbounds(inbounds); got != 0 {
		t.Fatalf("countEnabledInbounds(all disabled) = %d, want 0", got)
	}
	inbounds = append(inbounds, &model.Inbound{Id: 3, Enable: true})
	if got := countEnabledInbounds(inbounds); got != 1 {
		t.Fatalf("countEnabledInbounds(1 enabled) = %d, want 1", got)
	}
}
