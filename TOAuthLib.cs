////////////////////////////////////////////////////////////////////////////////
//
// TOAuthLib v1.3.6
// Require over .Net 4.0 or 2.0
// Made by RyuaNerin
// Last Update : 2015-02-17
//
// The MIT License (MIT)
//
// Copyright (c) 2015 RyuaNerin
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

#define USENET40

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Text;
using System.Net;
using System.Security.Cryptography;
using System.IO;
using System.Reflection;

#if USENET40
using System.Threading.Tasks;
#endif

namespace TOAuthLib
{
	public class TOAuth
	{
		[Serializable]
		public class TwitterException : Exception
		{
			internal TwitterException()
			{

			}
			internal TwitterException(Exception e, WebExceptionStatus status, string response)
				: base(response, e)
			{
				this.m_response = response;
				this.m_status = status;
			}

			public override string Message { get { return this.m_response; } }

			private WebExceptionStatus m_status;
			public WebExceptionStatus Status { get { return this.m_status; } }

			private string m_response;
			public string Response { get { return this.m_response; } }
		}

		public const string ContentType = "application/x-www-form-urlencoded";

		#region Constructor
		public TOAuth(string appToken, string appSecret) : this(appToken, appSecret, null, null)
		{
		}
		public TOAuth(string appToken, string appSecret, string userToken, string userSecret)
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

		public int TimeOut { get; set; }

		public IWebProxy Proxy { get; set; }
		#endregion

#if USENET40
		public string Call(string method, string uri, object data = null, string contentType = ContentType, string callback = null)
		{
			return Call(method, new Uri(TOAuth.FixUrl(uri)), data, contentType, callback);
		}
		public string Call(string method, Uri uri, object data = null, string contentType = ContentType, string callback = null)
		{
			using (Task<string> task = CallAsync(method, uri, data, contentType, callback))
			{
				task.Wait();
				return task.Result;
			}
		}
		
		public Task<string> CallAsync(string method, string uri, object data = null, string contentType = ContentType, string callback = null)
		{
			return CallAsync(method, new Uri(TOAuth.FixUrl(uri)), data, contentType, callback);
		}
		public Task<string> CallAsync(string method, Uri uri, object data = null, string contentType = ContentType, string callback = null)
		{
			IDictionary<string, object> dic;
			string str;
			byte[] arr;
			Stream stm;

			TOAuth.ParseData(ref uri, data, out dic, out str, out arr, out stm);

			return CallAsyncBase(method, uri, dic, str,arr, stm, contentType, callback);
		}
		private Task<string> CallAsyncBase(string method, Uri uri, IDictionary<string, object> dic, string str, byte[] arr, Stream stm, string contentType = ContentType, string callback = null)
		{
			method = method.ToUpper();

			return Task.Factory.StartNew<string>(() =>
				{
					Exception ex;

					try
					{
						HttpWebRequest req = this.MakeRequestBase(method, uri, dic, str, arr, stm, callback) as HttpWebRequest;
						req.AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip;

						if (!string.IsNullOrEmpty(contentType))
							req.ContentType = contentType;

						if (this.Proxy != null)
							req.Proxy = this.Proxy;

						if (method == "POST" && (stm != null || arr != null || dic != null || str != null))
						{
							if (stm != null)
							{
								if (stm.CanSeek) stm.Seek(0, SeekOrigin.Begin);

								req.ContentLength = stm.Length;
								WriteTo(stm, req.GetRequestStream());
							}
							else
							{
								Stream streamReq;
								if (arr != null)
									streamReq = new MemoryStream(arr);
								else if (dic != null)
									streamReq = new MemoryStream(Encoding.UTF8.GetBytes(TOAuth.ToString(dic, true)));
								else
									streamReq = new MemoryStream(Encoding.UTF8.GetBytes(str));

								using (streamReq)
								{
									req.ContentLength = streamReq.Length;
									WriteTo(streamReq, req.GetRequestStream());
								}
							}
						}

						using (WebResponse wres = req.GetResponse())
							using (Stream stream = wres.GetResponseStream())
								using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
									return reader.ReadToEnd();
					}
					catch (WebException e)
					{
						TwitterException te;

						if (e.Response != null)
						{
							using (e.Response)
							{
								using (Stream stream = e.Response.GetResponseStream())
								{
									using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
									{
										te = new TwitterException(e, e.Status, reader.ReadToEnd());
										reader.Close();
									}
								}
							}
							
							ex = te;
						}
						else
							ex = e;
					}
					catch (Exception e)
					{
						ex = e;
					}

					if (ex != null)
						throw ex;

					return null;
				});
		}
#else
		private class Async : IAsyncResult
		{
			public IAsyncResult		BaseAsync;
			public HttpWebRequest	Request;
			public AsyncCallback	CallBack;
			public Stream			Stream;
			public bool				EmbStream;
			public string			Result;
			public Exception		Exception;
			
			private ManualResetEvent m_waitHandle = new ManualResetEvent(false);
			public  ManualResetEvent AsyncWaitHandle { get { return this.m_waitHandle; } }
			WaitHandle  IAsyncResult.AsyncWaitHandle { get { return this.m_waitHandle; } }
			
			public object       AsyncState;
			object IAsyncResult.AsyncState { get { return this.AsyncState; } }
			
			public bool       IsCompleted;
			bool IAsyncResult.IsCompleted { get { return this.IsCompleted; } }
			
			public bool       CompletedSynchronously;
			bool IAsyncResult.CompletedSynchronously { get { return this.CompletedSynchronously; } }
		}

		public string Call(string method, string uri, object data = null, string contentType = ContentType, string callback = null, AsyncCallback asyncCallback = null, object state = null)
		{
			return Call(method, new Uri(TOAuth.FixUrl(uri)), data, contentType, callback, asyncCallback, state);
		}
		public string Call(string method, Uri uri, object data = null, string contentType = ContentType, string callback = null, AsyncCallback asyncCallback = null, object state = null)
		{
			IAsyncResult task = BeginCall(method, uri, data, contentType, callback, asyncCallback, state);
			task.AsyncWaitHandle.WaitOne(this.TimeOut);
			return EndCall(task);
		}

		public IAsyncResult BeginCall(string method, string uri, object data = null, string contentType = ContentType, string callback = null, AsyncCallback asyncCallback = null, object state = null)
		{
			return BeginCall(method, new Uri(TOAuth.FixUrl(uri)), data, contentType, callback, asyncCallback, state);
		}
		public IAsyncResult BeginCall(string method, Uri uri, object data = null, string contentType = ContentType, string callback = null, AsyncCallback asyncCallback = null, object state = null)
		{
			IDictionary<string, object> dic;
			string str;
			byte[] arr;
			Stream stm;

			TOAuth.ParseData(ref uri, data, out dic, out str, out arr, out stm);

			return BeginCallBase(method, uri, dic, str, arr, stm, contentType, callback, asyncCallback, state);
		}
		private IAsyncResult BeginCallBase(string method, Uri uri, IDictionary<string, object> dic, string str, byte[] arr, Stream stm, string contentType = ContentType, string callback = null, AsyncCallback asyncCallback = null, object state = null)
		{
			method = method.ToUpper();

			Async asc = new Async();

			asc.CallBack = asyncCallback;
			asc.AsyncState = state;

			asc.Request = this.MakeRequestBase(method, uri, dic, str, arr, stm, callback) as HttpWebRequest;
			asc.Request.AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip;

			if (!string.IsNullOrEmpty(contentType))
				asc.Request.ContentType = contentType;

			if (this.Proxy != null)
				asc.Request.Proxy = this.Proxy;

			if (method == "POST" && (stm != null || arr != null || dic != null || str != null))
			{
				if (stm != null)
				{
					asc.Stream = stm;
				}
				else
				{
					if (arr != null)
						asc.Stream = new MemoryStream(arr);
					else if (dic != null)
						asc.Stream = new MemoryStream(Encoding.UTF8.GetBytes(TOAuth.ToString(dic, true)));
					else
						asc.Stream = new MemoryStream(Encoding.UTF8.GetBytes(str));

					asc.EmbStream = true;
				}

				asc.Request.ContentLength = asc.Stream.Length;

				asc.BaseAsync = asc.Request.BeginGetRequestStream(this.CallbackUpload, asc);
			}
			else
			{
				asc.BaseAsync = asc.Request.BeginGetResponse(this.CallbackDownload, asc);
			}

			return asc;
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

		private void CallbackUpload(IAsyncResult o)
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

				async.BaseAsync = async.Request.BeginGetResponse(this.CallbackDownload, async);
			}
			catch (Exception e)
			{
				this.ErrorSet(e, async);
			}
		}
		private void CallbackDownload(IAsyncResult o)
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

				try
				{
					async.Request.Abort();
				}
				catch { }

				async.IsCompleted = true;

				async.AsyncWaitHandle.Set();
				if (async.CallBack != null)
					async.CallBack.Invoke(async);
			}
			catch (Exception e)
			{
				this.ErrorSet(e, async);
			}
		}

		private void ErrorSet(Exception e, Async async)
		{
			try
			{
				if (e is WebException)
				{
					WebException we = e as WebException;
		
					TwitterException te;

					using (we.Response)
					{
						using (StreamReader reader = new StreamReader(we.Response.GetResponseStream(), Encoding.UTF8))
						{
							te = new TwitterException(e, we.Status, reader.ReadToEnd());
							reader.Close();
						}
						we.Response.Close();
					}
				
					async.Exception = te;
				}
				else
				{
					async.Exception = e;
				}

				try
				{
					async.Request.Abort();
				}
				catch { }
			}
			catch { }

			async.IsCompleted = true;

			async.AsyncWaitHandle.Set();
			if (async.CallBack != null)
				async.CallBack.Invoke(async);
		}
#endif

		#region Make Request
		public WebRequest MakeRequest(string method, string uri, object data, string callback = null)
		{
			return MakeRequest(method, new Uri(TOAuth.FixUrl(uri)), data, callback);
		}
		public WebRequest MakeRequest(string method, Uri uri, object data, string callback = null)
		{
			IDictionary<string, object> dic;
			string str;
			byte[] arr;
			Stream stm;

			TOAuth.ParseData(ref uri, data, out dic, out str, out arr, out stm);

			return MakeRequestBase(method, uri, dic, str, arr, stm, callback);
		}
		private WebRequest MakeRequestBase(string method, Uri uri, IDictionary<string, object> dic, string str, byte[] arr, Stream stm, string callback = null)
		{
			method = method.ToUpper();

			Dictionary<string, object> dicParams = new Dictionary<string, object>();

			if (!string.IsNullOrEmpty(uri.Query))
				TOAuth.AddDictionary(dicParams, TOAuth.ToDictionary(uri.Query));

			if (dic != null)
				TOAuth.AddDictionary(dicParams, dic, true);

			if (!string.IsNullOrEmpty(str))
				TOAuth.AddDictionary(dicParams, TOAuth.ToDictionary(str));

			if (method == "GET" && dicParams != null)
				uri = new UriBuilder(uri) { Query = TOAuth.ToString(dicParams) }.Uri;

			HttpWebRequest req = (HttpWebRequest)WebRequest.Create(uri);
			req.Method = method;
			req.Timeout	= this.TimeOut;

			if (this.Proxy != null)
				req.Proxy = this.Proxy;

			req.UserAgent = "TOAuth v1.3.0";
			req.Headers.Add("Authorization", this.GetOAuthBase(method, uri, dicParams, callback));

			return req;
		}
		#endregion

		#region Create OAuth
		private static string[] oauth_array = { "oauth_consumer_key", "oauth_version", "oauth_nonce", "oauth_signature", "oauth_signature_method", "oauth_timestamp", "oauth_token", "oauth_callback" };

		private string GetOAuthBase(string method, Uri uri, IDictionary<string, object> param, string callback = null)
		{
			string nonce = TOAuth.GetNonce();
			long timestamp = TOAuth.GetTimeStamp();

			IDictionary<string, object> dicSorted = new SortedDictionary<string, object>();

			if (param != null)
				TOAuth.AddDictionary(dicSorted, param);

			if (callback != null)
				dicSorted.Add("oauth_callback", TOAuth.UrlEncode(callback));

			if (this.UserToken != null)
				dicSorted.Add("oauth_token", TOAuth.UrlEncode(this.UserToken));

			dicSorted.Add("oauth_consumer_key",		TOAuth.UrlEncode(this.AppToken));
			dicSorted.Add("oauth_nonce",			nonce);
			dicSorted.Add("oauth_timestamp",		timestamp);
			dicSorted.Add("oauth_signature_method",	"HMAC-SHA1");
			dicSorted.Add("oauth_version",			"1.0");

			string hashKey;
			if (string.IsNullOrEmpty(this.UserSecret))
				hashKey = string.Format("{0}&", TOAuth.UrlEncode(this.AppSecret));
			else
				hashKey = string.Format("{0}&{1}", TOAuth.UrlEncode(this.AppSecret), TOAuth.UrlEncode(this.UserSecret));

			string hashData = string.Format(
					"{0}&{1}&{2}",
					method.ToUpper(),
					TOAuth.UrlEncode(string.Format("{0}{1}{2}{3}", uri.Scheme, Uri.SchemeDelimiter, uri.Host, uri.AbsolutePath)),
					TOAuth.UrlEncode(TOAuth.ToString(dicSorted))
					);

			string sig;

			using (HMACSHA1 oCrypt = new HMACSHA1())
			{
				oCrypt.Key = Encoding.UTF8.GetBytes(hashKey);
				sig = Convert.ToBase64String(oCrypt.ComputeHash(Encoding.UTF8.GetBytes(hashData)));
			}

			dicSorted.Add("oauth_signature", TOAuth.UrlEncode(sig));

			StringBuilder sbData = new StringBuilder();
			sbData.Append("OAuth ");
			foreach (KeyValuePair<string, object> st in dicSorted)
				if (Array.IndexOf<string>(oauth_array, st.Key) >= 0)
					sbData.AppendFormat("{0}=\"{1}\",", st.Key, Convert.ToString(st.Value));
			sbData.Remove(sbData.Length - 1, 1);

			return sbData.ToString();
		}
		#endregion

		#region Static Functions
		private static void ParseData(ref Uri uri, object data, out IDictionary<string, object> outDic, out string outStr, out byte[] outArr, out Stream outStm)
		{
			uri = TOAuth.FixUri(uri);

			outDic = null;
			outStr = null;
			outArr = null;
			outStm = null;

			if (data == null) return;

			if (data is IDictionary<string, object>)
				outDic = data as IDictionary<string, object>;

			else if (data is string)
				outStr = data as string;

			else if (data is byte[])
				outArr = data as byte[];

			else if (data is Stream)
				outStm = data as Stream;

			else
				outDic = TOAuth.ToDictionary(data);
		}

		private static void WriteTo(Stream source, Stream desc)
		{
			byte[] buff = new byte[4096];
			int read;

			while ((read = source.Read(buff, 0, 4096)) > 0)
				desc.Write(buff, 0, read);
		}

		private static string UrlEncode(string value)
		{
			StringBuilder sb = new StringBuilder(value.Length);
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
		private static string GetNonce()
		{
			return rnd.Next(int.MinValue, int.MaxValue).ToString("X");
		}

		private static DateTime GenerateTimeStampDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0);
		private static long GetTimeStamp()
		{
			return Convert.ToInt64((DateTime.UtcNow - GenerateTimeStampDateTime).TotalSeconds);
		}

		private static string ToString(IDictionary<string, object> dic, bool useEncoding = false)
		{
			StringBuilder sb = new StringBuilder();

			if (dic.Count > 0)
			{
				if (useEncoding)
					foreach (KeyValuePair<string, object> st in dic)
						if (st.Value is bool)
							sb.AppendFormat("{0}={1}&", st.Key, (bool)st.Value ? "true" : "false");
						else
							sb.AppendFormat("{0}={1}&", st.Key, UrlEncode(Convert.ToString(st.Value)));
				else
					foreach (KeyValuePair<string, object> st in dic)
						if (st.Value is bool)
							sb.AppendFormat("{0}={1}&", st.Key, (bool)st.Value ? "true" : "false");
						else
							sb.AppendFormat("{0}={1}&", st.Key, Convert.ToString(st.Value));

				sb.Remove(sb.Length - 1, 1);
			}

			return sb.ToString();
		}

		private static IDictionary<string, object> ToDictionary(string str)
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

						read = find + 1;
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

		private static IDictionary<string, object> ToDictionary(object values)
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

		private static IDictionary<string, object> AddDictionary(IDictionary<string, object> dic, IDictionary<string, object> values, bool useEncoding = false)
		{
			if (useEncoding)
				foreach (KeyValuePair<string, object> st in values)
					if (dic.ContainsKey(st.Key))
						dic[st.Key] = TOAuth.UrlEncode(Convert.ToString(st.Value));
					else
						dic.Add(st.Key, TOAuth.UrlEncode(Convert.ToString(st.Value)));
			else
				foreach (KeyValuePair<string, object> st in values)
					if (dic.ContainsKey(st.Key))
						dic[st.Key] = st.Value;
					else
						dic.Add(st.Key, st.Value);


			return dic;
		}

		private static string FixUrl(string urlOrig)
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

		private static Uri FixUri(Uri uri)
		{
			if (uri.Scheme == "http")
				return new UriBuilder(uri) { Scheme = "https" }.Uri;
			else
				return uri;
		}
		#endregion
	}
}
