package axes_test

import (
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
)

func TestAxisStringValues(t *testing.T) {
	tests := []struct {
		axis axes.Axis
		want string
	}{
		{axes.Security, "security"},
		{axes.PermissionHygiene, "permission_hygiene"},
		{axes.Transparency, "transparency"},
		{axes.Quality, "quality"},
	}
	for _, tt := range tests {
		if string(tt.axis) != tt.want {
			t.Errorf("axis %v = %q, want %q", tt.axis, string(tt.axis), tt.want)
		}
	}
}

func TestAxisOrderIsStable(t *testing.T) {
	want := []axes.Axis{axes.Security, axes.PermissionHygiene, axes.Transparency, axes.Quality}
	if len(axes.Order) != len(want) {
		t.Fatalf("Order length = %d, want %d", len(axes.Order), len(want))
	}
	for i, a := range want {
		if axes.Order[i] != a {
			t.Errorf("Order[%d] = %v, want %v", i, axes.Order[i], a)
		}
	}
}

func TestGradeValues(t *testing.T) {
	grades := []axes.Grade{axes.GradeA, axes.GradeB, axes.GradeC, axes.GradeD, axes.GradeF}
	want := []string{"A", "B", "C", "D", "F"}
	for i, g := range grades {
		if string(g) != want[i] {
			t.Errorf("grade %v = %q, want %q", g, string(g), want[i])
		}
	}
}
