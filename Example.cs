tw.Call("get", "https://api.twitter.com/1.1/users/show.json?screen_name=_ryuarin")

tw.Call("get", "https://api.twitter.com/1.1/users/show.json", "screen_name=_ryuarin&count=200");

tw.Call("get", "https://api.twitter.com/1.1/users/show.json?screen_name=_ryuarin", new { count = 200 });

Dictionary<string, object> dic = new Dictionary<string, object>();
dic.Add("screen_name", "_ryuarin");
dic.Add("count", "200");
tw.Call("get", "https://api.twitter.com/1.1/users/show.json", dic);



tw.Call("post", "https://api.twitter.com/1.1/statuses/update.json?status=Test");
tw.Call("post", "https://api.twitter.com/1.1/statuses/update.json", new { status = "Test" });
tw.Call("post", "https://api.twitter.com/1.1/statuses/update.json", "status=Test");
