////////////////////////////////////////////////////////////////////////////////
//
// RyuaNerin OAuth-Twitter Library v1.1.0
// Maked by RyuaNerin
// Last Update : 2014-08-11
// The MIT License (MIT)

// Copyright (c) 2014, RyuaNerin
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
////////////////////////////////////////////////////////////////////////////////

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Text;
using System.Net;
using System.Security.Cryptography;
using System.IO;
using System.Reflection;

namespace RyuaNerin.OAuth
{
	internal static class OAuthUtils
	{
		public static string UrlEncode(string value)
		{
			StringBuilder sb = new StringBuilder();
			byte[] buff = Encoding.UTF8.GetBytes(value);

			for (int i = 0; i < buff.Length; ++i)
			{
				if (('a' <= buff[i] && buff[i] <= 'z') ||
					('A' <= buff[i] && buff[i] <= 'Z') ||
					('0' <= buff[i] && buff[i] <= '9') ||
					('-' == buff[i]) ||
					('_' == buff[i]) ||
					('.' == buff[i]) ||
					('~' == buff[i]))
					sb.Append((char)buff[i]);
				else
					sb.AppendFormat("%{0:X2}", buff[i]);
			}

			return sb.ToString();
		}

		private static Random rnd = new Random(DateTime.Now.Millisecond);
		public static string GetNonce()
		{
			return rnd.Next(int.MinValue, int.MaxValue).ToString("X");
		}

		private static DateTime GenerateTimeStampDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0);
		public static long GetTimeStamp()
		{
			return Convert.ToInt64((DateTime.UtcNow - GenerateTimeStampDateTime).TotalSeconds);
		}

		public static IDictionary<string, object> StringToDic(string str)
		{
			Dictionary<string, object> dic = new Dictionary<string, object>();

			if (!string.IsNullOrEmpty(str) || (str.Length > 1))
			{
				int read = 0;
				int find = 0;

				if (str[0] == '?')
					read = 1;

				string key, val;

				while (read < str.Length)
				{
					find = str.IndexOf('=', read);
					key = str.Substring(read, find - read);
					read = find + 1;

					find = str.IndexOf('&', read);
					if (find > 0)
					{
						if (find - read == 1)
							val = null;
						else
							val = str.Substring(read, find - read);

						read = find;
					}
					else
					{
						val = str.Substring(read);

						read = str.Length;
					}

					dic.Add(key, val);
				}
			}

			return dic;
		}

		public static string DicToString(IDictionary<string, object> dic)
		{
			StringBuilder sb = new StringBuilder();

			if (dic.Count > 0)
			{
				foreach (KeyValuePair<string, object> st in dic)
					if (st.Value is bool)
						sb.AppendFormat("{0}={1}&", st.Key, (bool)st.Value ? "true" : "false");
					else
						sb.AppendFormat("{0}={1}&", st.Key, Convert.ToString(st.Value));

				sb.Remove(sb.Length - 1, 1);
			}

			return sb.ToString();
		}

		public static string DicToStringWithEncode(IDictionary<string, object> dic)
		{
			StringBuilder sb = new StringBuilder();

			if (dic.Count > 0)
			{
				foreach (KeyValuePair<string, object> st in dic)
					if (st.Value is bool)
						sb.AppendFormat("{0}={1}&", st.Key, (bool)st.Value ? "true" : "false");
					else
						sb.AppendFormat("{0}={1}&", st.Key, UrlEncode(Convert.ToString(st.Value)));

				sb.Remove(sb.Length - 1, 1);
			}

			return sb.ToString();
		}

		public static IDictionary<string, object> PropertyToDic(object values)
		{
			try
			{
				Dictionary<string, object> dic = new Dictionary<string, object>();

				foreach (PropertyInfo p in values.GetType().GetProperties())
				{
					if (!p.CanRead) continue;
					dic.Add(Convert.ToString(p.Name), p.GetValue(values, null));
				}

				return dic;
			}
			catch
			{
				throw new FormatException();
			}
		}

		public static IDictionary<string, object> AddRange(this IDictionary<string, object> dic, IDictionary<string, object> values)
		{
			foreach (KeyValuePair<string, object> st in values)
				if (dic.ContainsKey(st.Key))
					dic[st.Key] = st.Value;
				else
					dic.Add(st.Key, st.Value);

			return dic;
		}

		public static IDictionary<string, object> AddRangeWithEncode(this IDictionary<string, object> dic, IDictionary<string, object> values)
		{
			foreach (KeyValuePair<string, object> st in values)
				if (dic.ContainsKey(st.Key))
					dic[st.Key] = OAuthUtils.UrlEncode(Convert.ToString(st.Value));
				else
					dic.Add(st.Key, OAuthUtils.UrlEncode(Convert.ToString(st.Value)));

			return dic;
		}

		public static string FixUrl(string urlOrig)
		{
			urlOrig = urlOrig.Trim();

			if (!urlOrig.StartsWith("https://") && !urlOrig.StartsWith("http://"))
			{
				StringBuilder sb = new StringBuilder();

				int pos = 0;
				int find = 0;

				sb.Append('/');
				if (urlOrig.IndexOf("/") == 0)
					pos += 1;

				sb.Append("1.1/");
				find = urlOrig.IndexOf("1.1/");
				if (find == 0 || find == pos)
					pos += 4;

				if (urlOrig.IndexOf("site.json") == pos ||
					urlOrig.IndexOf("user.json") == pos ||
					urlOrig.IndexOf("statuses/filter.json") == pos ||
					urlOrig.IndexOf("statuses/firehose.json") == pos ||
					urlOrig.IndexOf("statuses/sample.json") == pos
				)
					sb.Insert(0, "https://userstream.twitter.com");
				else
					sb.Insert(0, "https://api.twitter.com");

				sb.Append(urlOrig, pos, urlOrig.Length - pos);

				return sb.ToString();
			}
			else if (urlOrig.StartsWith("http://"))
			{
				return urlOrig.Replace("http://", "https://");
			}
			else
			{
				return urlOrig;
			}
		}

		public static Uri FixUri(Uri uri)
		{
			if (uri.Scheme == "http")
				return new UriBuilder(uri) { Scheme = "https" }.Uri;
			else
				return uri;
		}
	}

	public class Twitter
	{
		private const string ContentType = "application/x-www-form-urlencoded";

		private class Async : IAsyncResult
		{
			public Async()
			{
				this.m_waitHandle = new ManualResetEvent(false);
			}

			public IAsyncResult BaseAsync { get; set; }

			public WebRequest Request { get; set; }

			public AsyncCallback CallBack { get; set; }

			public Stream Stream { get; set; }
			public bool EmbStream { get; set; }

			public string Result { get; set; }

			public Exception Exception { get; set; }

			private ManualResetEvent m_waitHandle;
			public ManualResetEvent AsyncWaitHandle { get { return this.m_waitHandle; } }
			public object AsyncState { get; set; }
			public bool IsCompleted { get; set; }
			public bool CompletedSynchronously { get; set; }

			WaitHandle IAsyncResult.AsyncWaitHandle { get { return this.m_waitHandle; } }
			object IAsyncResult.AsyncState { get { return this.AsyncState; } }
			bool IAsyncResult.IsCompleted { get { return this.IsCompleted; } }
			bool IAsyncResult.CompletedSynchronously { get { return this.CompletedSynchronously; } }
		}

		#region Constructor
		public Twitter(string appToken, string appSecret)
			: this(appToken, appSecret, null, null)
		{
		}
		public Twitter(string appToken, string appSecret, string userToken, string userSecret)
		{
			this.AppToken = appToken;
			this.AppSecret = appSecret;

			this.UserToken = userToken;
			this.UserSecret = userSecret;

			this.TimeOut = 30 * 1000;
		}
		#endregion

		#region Propertiy
		public string AppToken { get; set; }
		public string AppSecret { get; set; }

		public string UserToken { get; set; }
		public string UserSecret { get; set; }

		public string CallBack { get; set; }

		public int TimeOut { get; set; }

		public IWebProxy Proxy { get; set; }
		#endregion

		#region Call
		public string Call(string method, string uri)
		{
			return this.CallBase(method, new Uri(OAuthUtils.FixUrl(uri)), null, null, null, null, null);
		}
		public string Call(string method, string uri, IDictionary<string, object> dic, string contentType = ContentType)
		{
			return this.CallBase(method, new Uri(OAuthUtils.FixUrl(uri)), dic, null, null, null, contentType);
		}
		public string Call(string method, string uri, object properties, string contentType = ContentType)
		{
			return this.CallBase(method, new Uri(OAuthUtils.FixUrl(uri)), OAuthUtils.PropertyToDic(properties), null, null, null, contentType);
		}
		public string Call(string method, string uri, string data, string contentType = ContentType)
		{
			return this.CallBase(method, new Uri(OAuthUtils.FixUrl(uri)), null, data, null, null, contentType);
		}
		public string Call(string method, string uri, byte[] array, string contentType = ContentType)
		{
			return this.CallBase(method, new Uri(OAuthUtils.FixUrl(uri)), null, null, array, null, contentType);
		}
		public string Call(string method, string uri, Stream stream, string contentType = ContentType)
		{
			return this.CallBase(method, new Uri(OAuthUtils.FixUrl(uri)), null, null, null, stream, contentType);
		}

		private string CallBase(string method, Uri uri, IDictionary<string, object> dic, string bodyString, byte[] bodyArray, Stream stream, string contentType)
		{
			IAsyncResult result = BeginCallBase(method, uri, dic, bodyString, bodyArray, stream, contentType, null, null);
			result.AsyncWaitHandle.WaitOne();
			return this.EndCall(result);
		}
		#endregion

		#region Async
		public IAsyncResult BeginCall(string method, Uri uri, AsyncCallback callBack = null, object state = null)
		{
			return this.BeginCallBase(method, OAuthUtils.FixUri(uri), null, null, null, null, null, callBack, state);
		}
		public IAsyncResult BeginCall(string method, Uri uri, IDictionary<string, object> dic, string contentType = ContentType, AsyncCallback callBack = null, object state = null)
		{
			return this.BeginCallBase(method, OAuthUtils.FixUri(uri), dic, null, null, null, contentType, callBack, state);
		}
		public IAsyncResult BeginCall(string method, Uri uri, object properties, string contentType = ContentType, AsyncCallback callBack = null, object state = null)
		{
			return this.BeginCallBase(method, OAuthUtils.FixUri(uri), OAuthUtils.PropertyToDic(properties), null, null, null, contentType, callBack, state);
		}
		public IAsyncResult BeginCall(string method, Uri uri, string data, string contentType = ContentType, AsyncCallback callBack = null, object state = null)
		{
			return this.BeginCallBase(method, OAuthUtils.FixUri(uri), null, data, null, null, contentType, callBack, state);
		}
		public IAsyncResult BeginCall(string method, Uri uri, byte[] array, string contentType = ContentType, AsyncCallback callBack = null, object state = null)
		{
			return this.BeginCallBase(method, OAuthUtils.FixUri(uri), null, null, array, null, contentType, callBack, state);
		}
		public IAsyncResult BeginCall(string method, Uri uri, Stream stream, string contentType = ContentType, AsyncCallback callBack = null, object state = null)
		{
			return this.BeginCallBase(method, OAuthUtils.FixUri(uri), null, null, null, stream, contentType, callBack, state);
		}

		private IAsyncResult BeginCallBase(string method, Uri uri, IDictionary<string, object> dic, string data, byte[] array, Stream stream, string contentType, AsyncCallback callBack, object state)
		{
			method = method.ToUpper();

			Async async = new Async();

			async.AsyncState = state;

			IDictionary<string, object> dicParam = new Dictionary<string, object>();

			if (!string.IsNullOrEmpty(uri.Query))
				dicParam.AddRange(OAuthUtils.StringToDic(uri.Query));
			if (!string.IsNullOrEmpty(data))
				dicParam.AddRange(OAuthUtils.StringToDic(data));
			if (dic != null)
				dicParam.AddRangeWithEncode(dic);

			async.Request = this.MakeRequestBase(method, uri, dicParam);

			if (!string.IsNullOrEmpty(contentType))
				async.Request.ContentType = contentType;

			if (this.Proxy != null)
				async.Request.Proxy = this.Proxy;

			async.Request.Timeout = this.TimeOut;

			if (method == "POST" && (stream != null || array != null || dic != null || data != null))
			{
				if (stream == null)
				{
					if (array != null)
						async.Stream = new MemoryStream(array);
					else if (dic != null)
						async.Stream = new MemoryStream(Encoding.UTF8.GetBytes(OAuthUtils.DicToStringWithEncode(dic)));
					else if (data != null)
						async.Stream = new MemoryStream(Encoding.UTF8.GetBytes(data));

					async.EmbStream = true;
				}
				else
				{
					async.Stream = stream;
					async.EmbStream = false;
				}

				async.Request.ContentLength = async.Stream.Length;

				async.BaseAsync = async.Request.BeginGetRequestStream(this.GetStream, async);
			}
			else
			{
				async.BaseAsync = async.Request.BeginGetResponse(this.GetResult, async);
			}

			return async;
		}

		public string EndCall(IAsyncResult asyncResult)
		{
			Async async = asyncResult as Async;

			if (async == null)
				throw new NotImplementedException();

			async.CompletedSynchronously = true;

			if (async.Exception != null)
				throw async.Exception;

			return async.Result;
		}

		private void GetStream(IAsyncResult o)
		{
			Async async = (Async)o.AsyncState;

			try
			{
				Stream stream = async.Request.EndGetRequestStream(async.BaseAsync);

				byte[] buff = new byte[4096];
				int read;
				while ((read = async.Stream.Read(buff, 0, 4096)) > 0)
					stream.Write(buff, 0, read);

				if (async.EmbStream)
					async.Stream.Dispose();

				async.BaseAsync = async.Request.BeginGetResponse(this.GetResult, async);
			}
			catch (Exception e)
			{
				try
				{
					async.Request.Abort();
				}
				catch
				{ }

				async.Exception = e;
				async.Result = null;

				async.AsyncWaitHandle.Set();
				if (async.CallBack != null)
					async.CallBack.Invoke(async);
			}
		}

		private void GetResult(IAsyncResult o)
		{
			Async async = (Async)o.AsyncState;

			try
			{
				using (WebResponse wres = async.Request.EndGetResponse(async.BaseAsync))
				{
					using (StreamReader reader = new StreamReader(wres.GetResponseStream(), Encoding.UTF8))
					{
						async.Result = reader.ReadToEnd();
						reader.Close();
					}
					wres.Close();
				}
			}
			catch (Exception e)
			{
				async.Exception = e;
				async.Result = null;
			}

			try
			{
				async.Request.Abort();
			}
			catch
			{ }

			async.AsyncWaitHandle.Set();
			if (async.CallBack != null)
				async.CallBack.Invoke(async);
		}
		#endregion

		#region GetRequest
		public WebRequest MakeRequest(string method, Uri uri)
		{
			return this.MakeRequestBase(method, OAuthUtils.FixUri(uri), null);
		}
		public WebRequest MakeRequest(string method, Uri uri, IDictionary<string, object> dic)
		{
			return this.MakeRequestBase(method, OAuthUtils.FixUri(uri), OAuthUtils.StringToDic(uri.Query).AddRangeWithEncode(dic));
		}
		public WebRequest MakeRequest(string method, Uri uri, object properties)
		{
			return this.MakeRequestBase(method, OAuthUtils.FixUri(uri), OAuthUtils.StringToDic(uri.Query).AddRangeWithEncode(OAuthUtils.PropertyToDic(properties)));
		}
		public WebRequest MakeRequest(string method, Uri uri, string data)
		{
			return this.MakeRequestBase(method, OAuthUtils.FixUri(uri), OAuthUtils.StringToDic(uri.Query).AddRange(OAuthUtils.StringToDic(data)));
		}

		private WebRequest MakeRequestBase(string method, Uri uri, IDictionary<string, object> dicParam)
		{
			method = method.ToUpper();

			if (method == "GET" && dicParam != null)
				uri = new UriBuilder(uri) { Query = OAuthUtils.DicToString(dicParam) }.Uri;

			WebRequest req = WebRequest.Create(uri);
			req.Method = method;

			if (this.Proxy != null)
				req.Proxy = this.Proxy;

			req.Headers.Add("Authorization", this.GetOAuthBase(method, uri, dicParam));

			return req;
		}
		#endregion

		#region Create OAuth
		private static string[] oauth_array = { "oauth_consumer_key", "oauth_version", "oauth_nonce", "oauth_signature", "oauth_signature_method", "oauth_timestamp", "oauth_token", "oauth_callback" };

		private string GetOAuthBase(string method, Uri uri, IDictionary<string, object> param)
		{
			string nonce = OAuthUtils.GetNonce();
			long timestamp = OAuthUtils.GetTimeStamp();

			IDictionary<string, object> dicSorted = new SortedDictionary<string, object>();
			if (param != null)
				dicSorted.AddRange(param);

			if (this.CallBack != null)
				dicSorted.Add("oauth_callback", OAuthUtils.UrlEncode(this.CallBack));

			if (this.UserToken != null)
				dicSorted.Add("oauth_token", OAuthUtils.UrlEncode(this.UserToken));

			dicSorted.Add("oauth_consumer_key", OAuthUtils.UrlEncode(this.AppToken));
			dicSorted.Add("oauth_nonce", nonce);
			dicSorted.Add("oauth_timestamp", timestamp);
			dicSorted.Add("oauth_signature_method", "HMAC-SHA1");
			dicSorted.Add("oauth_version", "1.0");

			string hashKey;
			if (string.IsNullOrEmpty(this.UserSecret))
				hashKey = string.Format("{0}&", OAuthUtils.UrlEncode(this.AppSecret));
			else
				hashKey = string.Format("{0}&{1}", OAuthUtils.UrlEncode(this.AppSecret), OAuthUtils.UrlEncode(this.UserSecret));

			string hashData = string.Format(
					"{0}&{1}&{2}",
					method.ToUpper(),
					OAuthUtils.UrlEncode(string.Format("{0}{1}{2}{3}", uri.Scheme, Uri.SchemeDelimiter, uri.Host, uri.AbsolutePath)),
					OAuthUtils.UrlEncode(OAuthUtils.DicToString(dicSorted))
					);

			string sig;

			using (HMACSHA1 oCrypt = new HMACSHA1())
			{
				oCrypt.Key = Encoding.UTF8.GetBytes(hashKey);
				sig = Convert.ToBase64String(oCrypt.ComputeHash(Encoding.UTF8.GetBytes(hashData)));
			}

			dicSorted.Add("oauth_signature", sig);

			StringBuilder sbData = new StringBuilder();
			sbData.Append("OAuth ");
			foreach (KeyValuePair<string, object> st in dicSorted)
				if (Array.IndexOf<string>(oauth_array, st.Key) >= 0)
					sbData.AppendFormat("{0}=\"{1}\",", st.Key, OAuthUtils.UrlEncode(Convert.ToString(st.Value)));
			sbData.Remove(sbData.Length - 1, 1);

			this.CallBack = null;

			return sbData.ToString();
		}
		#endregion
	}
}
