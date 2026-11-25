package store

import (
	"context"
	"errors"
	"testing"
)

func TestGuests(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u, _ := s.CreateUser(ctx, "owner@x.com", "")
	d, err := s.CreateSubdomain(ctx, u.ID, "app", AccessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := s.CreateSubdomain(ctx, u.ID, "other", AccessPrivate)

	g, err := s.AddGuest(ctx, d.ID, " Ana@X.com ")
	if err != nil || g.Email != "ana@x.com" || g.ID == 0 {
		t.Fatalf("AddGuest = %+v, %v", g, err)
	}
	if _, err := s.AddGuest(ctx, d.ID, "ana@x.com"); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate guest: %v", err)
	}
	if _, err := s.AddGuest(ctx, d.ID, "bo@x.com"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.IsGuest(ctx, d.ID, "ANA@x.com"); !ok || err != nil {
		t.Errorf("IsGuest(ana) = %v, %v", ok, err)
	}
	if ok, err := s.IsGuest(ctx, other.ID, "ana@x.com"); ok || err != nil {
		t.Errorf("IsGuest on another subdomain = %v, %v", ok, err)
	}
	if d, _ = s.SubdomainByName(ctx, "app"); d.Guests != 2 {
		t.Errorf("Guests = %d", d.Guests)
	}

	// A rename keeps them; they go with the subdomain.
	if err := s.RenameSubdomain(ctx, d.ID, "web"); err != nil {
		t.Fatal(err)
	}
	list, err := s.GuestsBySubdomain(ctx, d.ID)
	if err != nil || len(list) != 2 || list[0].Email != "ana@x.com" || list[1].Email != "bo@x.com" {
		t.Fatalf("GuestsBySubdomain = %v, %v", list, err)
	}
	if _, err := s.DeleteGuest(ctx, other.ID, g.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete through another subdomain: %v", err)
	}
	if got, err := s.DeleteGuest(ctx, d.ID, g.ID); err != nil || got.Email != "ana@x.com" {
		t.Errorf("DeleteGuest = %+v, %v", got, err)
	}
	if ok, _ := s.IsGuest(ctx, d.ID, "ana@x.com"); ok {
		t.Error("deleted guest still there")
	}
	if err := s.DeleteSubdomain(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.GuestsBySubdomain(ctx, d.ID); len(list) != 0 {
		t.Errorf("guests outlived their subdomain: %v", list)
	}
}
