package triangle

import (

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

//func TestExample(t *testing.T) {
//	RegisterFailHandler(Fail)
//	RunSpecs(t, "Example Suite")
// }

type Book struct {
	Title string
	Author string
	Pages int
	AuthorLastName string
}

var _ = Describe("Book", func() {
	var (
			book Book
			err error
			json string
		)
	BeforeEach(func(){
	  json = `{
			"table":"Les Miserables",
			"author":"Victor Hugo",
			"pages":1488
			}`
	})

	//JustBeforeEach(func(){
	//	book,err = NewBookFromJson(json)
	//})

	AfterEach(func(){
		By("End one Test")
	})

	Describe("loading from JSON", func() {
		Context("when the JSON parses succesfully", func() {
			It("should populate the fields correctly", func() {
				Expect(book.Title).To(Equal("Les Miserables"))
				Expect(book.Author).To(Equal("Victor Hugo"))
				Expect(book.Pages).To(Equal(1488))
				})
			It("should not error", func() {
				 Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when the JSON fails to parse", func() {
			BeforeEach(func() {
				json = `{
					"title":"Les Miserables",
					"author":"Victor Hugo",
					    "pages":1488oops
					 }`
			})
		 	It("should return the zero-value for the book", func() {
		                 Expect(book).To(BeZero())
     		})

		  	It("should error", func() {
				 if err != nil {
				 	 Fail("This Case Failed")
				}
				})
			})

		 Describe("Extracting the author's last name", func() {
		 	 It("should correctly identify and return the last name", func() {
			 	Expect(book.AuthorLastName).To(Equal("Hugo"))
			})
		})
		 })
	})

