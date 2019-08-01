package triangle_0

import (
	"errors"
	"math"
	"sort"
)

type Kind int

const (
	NaT Kind = iota
	Equ
	Iso
	Sca
)

func KindFromSides1(a,b,c float64) (Kind,error)  {
	data := []float64{a,b,c}
	sort.Float64s(data)

	if data[0]+data[1]<data[2] || math.IsNaN(data[0]) || data[0] <=0 || math.Inf(1) == data[2]{
			return NaT,errors.New("Not a triangke")

	}

	if data[0] == data[1] && data[1] == data[2] {
		return Equ, nil
	}

	if data[0] == data[1] || data[1] == data[2] {
		return Iso, nil
	}

	return Sca, nil



}