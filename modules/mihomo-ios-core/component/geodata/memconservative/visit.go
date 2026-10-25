package memconservative

import (
	"fmt"
	"github.com/Dreamacro/clash/component/geodata/router"
	C "github.com/Dreamacro/clash/constant"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func (m *memConservativeLoader) VisitSiteByPath(filename, list string, visit func(*router.Domain) error) error {
	data, err := Decode(C.Path.GetAssetLocation(filename), list)
	if err != nil {
		return err
	}
	var domain router.Domain
	for len(data) > 0 {
		field, kind, n := protowire.ConsumeTag(data)
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]
		if field == 2 {
			if kind != protowire.BytesType {
				return fmt.Errorf("invalid geosite domain wire type")
			}
			raw, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return protowire.ParseError(n)
			}
			if err := proto.Unmarshal(raw, &domain); err != nil {
				return err
			}
			if err := visit(&domain); err != nil {
				return err
			}
			data = data[n:]
		} else {
			n := protowire.ConsumeFieldValue(field, kind, data)
			if n < 0 {
				return protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return nil
}
