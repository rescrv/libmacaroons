package macaroons

import (
	"strings"
	"time"

	gc "gopkg.in/check.v1"
)

func (s *Suite) TestVerifyExact(c *gc.C) {
	usernameRule := "username = tk421"
	locationRule := "location = cargo-bay-11"
	secret := "not a moon"

	m, err := NewMacaroon("death star", secret, "tk421@deathstar")
	c.Assert(err, gc.IsNil)
	defer m.Destroy()
	c.Assert(m, gc.NotNil)

	// no caveats, ok
	func() {
		v1 := NewVerifier()
		defer v1.Destroy()
		err = v1.Verify(m, secret)
		c.Assert(err, gc.IsNil)
	}()

	// wrong secret, err
	func() {
		v2 := NewVerifier()
		defer v2.Destroy()
		err = v2.Verify(m, "han shot first")
		c.Assert(err, gc.NotNil)
	}()

	// fail username caveat, err
	func() {
		m1, err := m.Copy()
		c.Assert(err, gc.IsNil)
		defer m1.Destroy()
		m1.WithFirstPartyCaveat("username = r2d2")

		v := NewVerifier()
		defer v.Destroy()
		v.SatisfyExact(usernameRule)
		v.SatisfyExact(locationRule)
		err = v.Verify(m1, secret)
		c.Assert(err, gc.NotNil, gc.Commentf("%+v", err)) // TK-421 is not at his post
	}()

	// fail location caveat, err
	func() {
		m2, err := m.Copy()
		c.Assert(err, gc.IsNil)
		defer m2.Destroy()
		m2.WithFirstPartyCaveat("username = tk421")
		m2.WithFirstPartyCaveat("location = detention-level-aa23")

		v := NewVerifier()
		v.SatisfyExact(usernameRule)
		v.SatisfyExact(locationRule)
		err = v.Verify(m2, secret)
		c.Assert(err, gc.NotNil) // TK-421 is not at his post
	}()

	// satisfy both caveats, ok
	func() {
		m3, err := m.Copy()
		c.Assert(err, gc.IsNil)
		defer m3.Destroy()
		m3.WithFirstPartyCaveat("username = tk421")
		m3.WithFirstPartyCaveat("location = cargo-bay-11")

		v := NewVerifier()
		v.SatisfyExact(usernameRule)
		v.SatisfyExact(locationRule)
		err = v.Verify(m3, secret)
		c.Assert(err, gc.IsNil, gc.Commentf("%+v", err)) // TK-421 is at his post
	}()
}

const timeLayout = "2006-01-02T15:04:05 -0700"

func checkTimeAt(nowString string) GeneralCaveat {
	now, err := time.Parse(timeLayout, nowString)
	if err != nil {
		panic(err)
	}
	return func(s string) bool {
		fields := strings.SplitN(s, " ", 3)
		if len(fields) != 3 {
			return false
		}
		if fields[0] != "time" {
			return false
		}
		if fields[1] != "<" {
			return false
		}
		deadline, err := time.Parse(timeLayout, fields[2])
		if err != nil {
			return false
		}
		return now.Before(deadline)
	}
}

func (s *Suite) TestVerifyGeneral(c *gc.C) {
	secret := "wait til you see those goddamn bats"
	m, err := NewMacaroon("The Mint Hotel", secret, "hst")
	c.Assert(err, gc.IsNil)
	defer m.Destroy()
	c.Assert(m, gc.NotNil)

	deadline := "time < 1971-11-11T16:00:00 -0800"

	func() {
		v := NewVerifier()
		err = v.SatisfyGeneral(checkTimeAt("2014-05-08T23:40:00 +0000"))
		c.Assert(err, gc.IsNil)

		m2, err := m.Copy()
		c.Assert(err, gc.IsNil)
		err = m2.WithFirstPartyCaveat(deadline)
		c.Assert(err, gc.IsNil)
		err = v.Verify(m2, secret)
		c.Assert(err, gc.NotNil)
	}()

	func() {
		v := NewVerifier()
		err = v.SatisfyGeneral(checkTimeAt("1971-11-11T15:59:59 -0800"))
		c.Assert(err, gc.IsNil)

		m2, err := m.Copy()
		c.Assert(err, gc.IsNil)
		err = m2.WithFirstPartyCaveat(deadline)
		c.Assert(err, gc.IsNil)
		err = v.Verify(m2, secret)
		c.Assert(err, gc.IsNil)
	}()
}

func (s *Suite) TestVerifyThirdParty(c *gc.C) {
	secret := "this is a different super-secret key; never use the same secret twice"
	public := "we used our other secret key"
	location := "http://mybank/"
	m, err := NewMacaroon(location, secret, public)
	c.Assert(err, gc.IsNil)
	defer m.Destroy()
	c.Assert(m, gc.NotNil)
	err = m.WithFirstPartyCaveat("account = 3735928559")
	c.Assert(err, gc.IsNil)

	caveatKey := "4; guaranteed random by a fair toss of the dice"
	identifier := "this was how we remind auth of key/pred"
	err = m.WithThirdPartyCaveat("http://auth.mybank/", caveatKey, identifier)
	c.Assert(err, gc.IsNil)

	discharge, err := NewMacaroon("http://auth.mybank/", caveatKey, identifier)
	c.Assert(err, gc.IsNil)
	defer discharge.Destroy()
	err = discharge.WithFirstPartyCaveat("time < 2015-01-01T00:00:00 +0000")
	c.Assert(err, gc.IsNil)

	preparedDischarge, err := m.PrepareForRequest(discharge)
	c.Assert(err, gc.IsNil)
	defer preparedDischarge.Destroy()

	v := NewVerifier()
	defer v.Destroy()
	err = v.SatisfyExact("account = 3735928559")
	c.Assert(err, gc.IsNil)
	err = v.SatisfyGeneral(checkTimeAt("2014-05-30T20:25:00 -0500"))
	c.Assert(err, gc.IsNil)
	err = v.Verify(m, secret, preparedDischarge)
	c.Assert(err, gc.IsNil)
}
