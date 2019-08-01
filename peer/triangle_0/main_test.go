package triangle_0

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Triangle", func() {

	BeforeEach(func() {
		fmt.Println("xxxxx")
	})
	It("Should return an error if the sides don't make up a triangle", func() {
		got,err :=KindFromSides1(0,-1,10)
		Expect(err).To(HaveOccurred())
		Expect(got).To(Equal(NaT))

	})
})
