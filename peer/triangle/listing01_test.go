package triangle

import (
	"net/http"
	"testing"
)

const checkMark  ="\u2713"
const ballotX  ="\u2717"

func TestDownload(t *testing.T){
	url := "http://www.goinggo.net/feeds/posts/default?alt=rss"
	statusCode :=200

	t.Log("Given the need to test dowbnloading content. ")
	{
		t.Logf("\tWhen checking \"%s\" for status code \"%d\" ",url,statusCode)
		{
			resp,err := http.Get(url)
			if err !=nil {
				t.Fatal("\t\t Should be able to make the Get call.",ballotX,err)
			}
			t.Log("\t\tShould be able to make the Get call.",
				checkMark)
			defer resp.Body.Close()

			if resp.StatusCode == statusCode {
				t.Logf("\t\t Should receive a \"%d\" status. %v ",
					statusCode, checkMark)
			}else {
				t.Error("\t\t Should receive a \"%d\" status. %v %v",
					statusCode, ballotX, resp.StatusCode)
			}
		}
	}
}
