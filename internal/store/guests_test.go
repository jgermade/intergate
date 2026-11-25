package store

import (
	"context"
	"errors"
	"testing"
)

func TestGuests(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	owner, _ := s.CreateUser(ctx, "owner@x.com", "")
	ana, _ := s.CreateUser(ctx, "ana@x.com", "Ana")
	bo, _ := s.CreateUser(ctx, "bo@x.com", "")
	cy, _ := s.CreateUser(ctx, "cy@x.com", "Abel")
	d, err := s.CreateSubdomain(ctx, owner.ID, "app", AccessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := s.CreateSubdomain(ctx, owner.ID, "other", AccessPrivate)

	if err := s.SetUserCanInvite(ctx, owner.ID, true); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.UserByID(ctx, owner.ID); !u.CanInvite {
		t.Error("can_invite not saved")
	}

	g, err := s.AddGuest(ctx, d.ID, ana.ID)
	if err != nil || g.Email != "ana@x.com" || g.Name != "Ana" || g.UserID != ana.ID || g.ID == 0 {
		t.Fatalf("AddGuest = %+v, %v", g, err)
	}
	if _, err := s.AddGuest(ctx, d.ID, ana.ID); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate guest: %v", err)
	}
	if _, err := s.AddGuest(ctx, d.ID, bo.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.IsGuest(ctx, d.ID, ana.ID); !ok || err != nil {
		t.Errorf("IsGuest(ana) = %v, %v", ok, err)
	}
	if ok, err := s.IsGuest(ctx, other.ID, ana.ID); ok || err != nil {
		t.Errorf("IsGuest on another subdomain = %v, %v", ok, err)
	}
	if d, _ = s.SubdomainByName(ctx, "app"); d.Guests != 2 {
		t.Errorf("Guests = %d", d.Guests)
	}

	// Candidates: neither the owner nor guests nor disabled accounts, by
	// name or else email.
	s.SetUserDisabled(ctx, bo.ID, true)
	list, err := s.GuestCandidates(ctx, other.ID)
	if err != nil || len(list) != 2 || list[0].Email != "cy@x.com" || list[1].Email != "ana@x.com" {
		t.Errorf("GuestCandidates(other) = %v, %v", list, err)
	}
	if list, _ := s.GuestCandidates(ctx, d.ID); len(list) != 1 || list[0].ID != cy.ID {
		t.Errorf("GuestCandidates(app) = %v", list)
	}

	// A rename keeps them; they go with the subdomain, or their account.
	if err := s.RenameSubdomain(ctx, d.ID, "web"); err != nil {
		t.Fatal(err)
	}
	guests, err := s.GuestsBySubdomain(ctx, d.ID)
	if err != nil || len(guests) != 2 || guests[0].Email != "ana@x.com" || guests[1].Email != "bo@x.com" {
		t.Fatalf("GuestsBySubdomain = %v, %v", guests, err)
	}
	if _, err := s.DeleteGuest(ctx, other.ID, g.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete through another subdomain: %v", err)
	}
	if got, err := s.DeleteGuest(ctx, d.ID, g.ID); err != nil || got.Email != "ana@x.com" {
		t.Errorf("DeleteGuest = %+v, %v", got, err)
	}
	if ok, _ := s.IsGuest(ctx, d.ID, ana.ID); ok {
		t.Error("deleted guest still there")
	}
	if err := s.DeleteUser(ctx, bo.ID); err != nil {
		t.Fatal(err)
	}
	if guests, _ := s.GuestsBySubdomain(ctx, d.ID); len(guests) != 0 {
		t.Errorf("guest outlived their account: %v", guests)
	}
	s.AddGuest(ctx, d.ID, cy.ID)
	if err := s.DeleteSubdomain(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if guests, _ := s.GuestsBySubdomain(ctx, d.ID); len(guests) != 0 {
		t.Errorf("guests outlived their subdomain: %v", guests)
	}
}
