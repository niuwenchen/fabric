package triangle

import (
	"net/http"
	"testing"
)



func TestDownloadN(t *testing.T){
	var urls = [] struct {
		url string
		stausCode int
	}{
		{
			"http://www.goinggo.net/feeds/posts/default?alt=rss",
			http.StatusOK,
		},
		{
			"http://rss.cnn.com/rss/cnn_topstbadurl.rss",
			http.StatusNotFound,
		},
	}

	t.Log("Given the need to test downloading different content.")
	{
		for _, u  :=range urls{
			t.Logf("\t When checking \"%s\" fir status code \"%d\"",u.url,u.stausCode)
			{
				resp,err := http.Get(u.url)
				if err !=nil {
					t.Fatal("\t\t Should be able to make the Get call.",ballotX,err)
				}
				t.Log("\t\tShould be able to make the Get call.",
					checkMark)

				defer resp.Body.Close()

				if resp.StatusCode == u.stausCode {
					t.Logf("\t\t Should have a \"%d\" status. %v ",
						u.stausCode, checkMark)
				}else {
					t.Error("\t\t Should have a \"%d\" status. %v %v",
						u.stausCode, ballotX, resp.StatusCode)
				}
			}
		}
	}

}

