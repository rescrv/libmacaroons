package macaroons

import (
	gc "gopkg.in/check.v1"
)

func (s *Suite) TestHelloMacaroons(c *gc.C) {
	m, err := NewMacaroon("test", "hunter2", "AzureDiamond")
	c.Assert(err, gc.IsNil)
	defer m.Destroy()
	c.Assert(m, gc.NotNil)

	c.Check(m.Location(), gc.Equals, "test")
	c.Check(m.Id(), gc.Equals, "AzureDiamond")

	err = m.WithFirstPartyCaveat("hello = world")
	c.Assert(err, gc.IsNil)

	err = m.Validate()
	c.Assert(err, gc.IsNil)

	out, err := m.Marshal()
	c.Assert(err, gc.IsNil)

	m2, err := Unmarshal(out)
	c.Assert(err, gc.IsNil)
	defer m2.Destroy()
	c.Check(m2.Signature(), gc.Equals, m.Signature())
	c.Check(m2.Location(), gc.Equals, "test")
	c.Check(m2.Id(), gc.Equals, "AzureDiamond")
	c.Check(Cmp(m, m2), gc.Equals, 0)

	err = m2.Validate()
	c.Assert(err, gc.IsNil)

	m3, err := m2.Copy()
	c.Assert(err, gc.IsNil)
	defer m3.Destroy()
	c.Check(m3.Signature(), gc.Equals, m.Signature())
	c.Check(m3.Location(), gc.Equals, "test")
	c.Check(m3.Id(), gc.Equals, "AzureDiamond")
	c.Check(Cmp(m, m3), gc.Equals, 0)
}

func (s *Suite) TestCaveatsChangeThings(c *gc.C) {
	m, err := NewMacaroon("pandora", "catch a ride", "scooter")
	c.Assert(err, gc.IsNil)
	defer m.Destroy()

	var last string
	for _, predicate := range []string{"roland", "mordecai", "lilith", "brick"} {
		err = m.WithFirstPartyCaveat(predicate)
		c.Assert(err, gc.IsNil)
		next, err := m.Marshal()
		c.Assert(err, gc.IsNil)

		c.Assert(next, gc.Not(gc.HasLen), 0)
		c.Assert(last, gc.Not(gc.Equals), next)
		last = next
	}

	for _, tp := range []struct {
		loc, key, id string
	}{
		{"axton", "commando", "turret"},
		{"maya", "siren", "phaselock"},
		{"salvador", "gunzerker", "dual-wield"},
		{"zero", "a number", "hologram"},
	} {
		err = m.WithThirdPartyCaveat(tp.loc, tp.key, tp.id)
		c.Assert(err, gc.IsNil)
		next, err := m.Marshal()
		c.Assert(err, gc.IsNil)

		c.Assert(next, gc.Not(gc.Equals), "")
		c.Assert(last, gc.Not(gc.Equals), next)
		last = next
	}

	tps, err := m.ThirdPartyCaveats()
	c.Assert(err, gc.IsNil)
	c.Assert(tps, gc.HasLen, 4)
	c.Check(tps[0], gc.DeepEquals, ThirdPartyId{Location: "axton", Id: "turret"})
	c.Check(tps[1], gc.DeepEquals, ThirdPartyId{Location: "maya", Id: "phaselock"})
	c.Check(tps[2], gc.DeepEquals, ThirdPartyId{Location: "salvador", Id: "dual-wield"})
	c.Check(tps[3], gc.DeepEquals, ThirdPartyId{Location: "zero", Id: "hologram"})
}

func (s *Suite) TestInspect(c *gc.C) {
	m, err := NewMacaroon("ingsoc", "under the spreading chestnut tree", "wsmith")
	c.Assert(err, gc.IsNil)
	defer m.Destroy()

	desc, err := m.Inspect()
	c.Assert(err, gc.IsNil)
	c.Check(desc, gc.Equals, `location ingsoc
identifier wsmith
signature d5c974d83f28c451f7955af20fd13c97296f0344f762bf7b89d91b31f2abdb30`)

	m.WithFirstPartyCaveat("war = peace")
	m.WithFirstPartyCaveat("slavery = freedom")
	m.WithFirstPartyCaveat("ignorance = strength")
	desc, err = m.Inspect()
	c.Check(desc, gc.Equals, `location ingsoc
identifier wsmith
cid war = peace
cid slavery = freedom
cid ignorance = strength
signature ef6e75301b1cafde6e87a1d44adab81b6492f5c11d51026c4a5be9beda1a07be`)
}
