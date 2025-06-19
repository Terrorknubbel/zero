package chat

import (
	"os"
	"testing"
	"time"

	"github.com/onsi/gomega"
)

func TestManagerEndToEnd(t *testing.T) {
	g := gomega.NewWithT(t)

	tmp, _ := os.MkdirTemp("", "mgr_*")
	defer os.RemoveAll(tmp)

	mgr, _ := NewManager(tmp, "Alice")
	g.Expect(mgr.Initialise()).To(gomega.Succeed())

	// Demo-Bob sollte vorhanden sein
	list, _ := mgr.Contacts()
	g.Expect(list).To(gomega.HaveLen(1))

	bobID := list[0].ID
	g.Expect(mgr.Send(bobID, "Hi Bob")).To(gomega.Succeed())

	// direkt nach dem Senden muss ein Log existieren
	msgs, _ := mgr.Messages(bobID, 0)
	g.Expect(msgs).To(gomega.HaveLen(1))
	g.Expect(msgs[0].Text).To(gomega.Equal("Hi Bob"))

	// Neustart → Manager lädt Log korrekt
	mgr2, _ := NewManager(tmp, "Alice")
	g.Expect(mgr2.Initialise()).To(gomega.Succeed())

	msgs2, _ := mgr2.Messages(bobID, 0)
	g.Expect(msgs2).To(gomega.HaveLen(1))
	g.Expect(msgs2[0].Text).To(gomega.Equal("Hi Bob"))
	g.Expect(msgs2[0].At.After(time.Time{})).To(gomega.BeTrue())
}
