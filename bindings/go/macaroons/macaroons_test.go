/* Copyright (c) 2014, Casey Marshall
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of this project nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
