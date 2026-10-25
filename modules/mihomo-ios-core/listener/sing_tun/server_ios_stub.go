//go:build ios && !with_gvisor

package sing_tun

import (
	E "github.com/sagernet/sing/common/exceptions"

	tun "github.com/metacubex/sing-tun"
)

func tunNew(options tun.Options) (tun.Tun, error) {
	return nil, E.New("iOS tun requires gVisor support; rebuild MihomoMobile with -tags with_gvisor")
}
