/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/
 */

#include "gme_tools.h"
#include "gme_netw.h"
#include "gme_logs.h"
#include "pugixml.hpp"
#include "winhttp.h"

/*
  function to encode url from string
*/
std::string GME_NetwEncodeUrl(const char* url)
{
  /*
    adapted from that: http://www.geekhideout.com/urlcode.shtml
    thanks to the author....
  */

  char hex[] = "0123456789abcdef";

  std::string encode;
  size_t s = strlen(url);

  for(unsigned i = 0; i < s; i++) {

    if(isalnum(url[i]) || url[i] == '-'
                       || url[i] == '_'
                       || url[i] == '.'
                       || url[i] == '~'
                       || url[i] == '/'
                       || url[i] == ':'
                       || url[i] == '?'
                       || url[i] == '%') {
      encode.append(1, url[i]);
    } else {
      encode.append(1, '%');
      encode.append(1, hex[(url[i] >> 4) & 15]);
      encode.append(1, hex[url[i] & 15]);
    }
  }

  return encode;
}


/*
  function to encode url from string
*/
std::string GME_NetwEncodeUrl(const std::string& url)
{
  /*
    adapted from that: http://www.geekhideout.com/urlcode.shtml
    thanks to the author....
  */

  char hex[] = "0123456789abcdef";

  std::string encode;
  size_t s = url.size();

  for(unsigned i = 0; i < s; i++) {

    if(isalnum(url[i]) || url[i] == '-'
                       || url[i] == '_'
                       || url[i] == '.'
                       || url[i] == '~'
                       || url[i] == '/'
                       || url[i] == ':'
                       || url[i] == '?'
                       || url[i] == '%') {
      encode.append(1, url[i]);
    } else {
      encode.append(1, '%');
      encode.append(1, hex[(url[i] >> 4) & 15]);
      encode.append(1, hex[url[i] & 15]);
    }
  }

  return encode;
}


/*
  function to decode url to string
*/
std::string GME_NetwDecodeUrl(const char* url)
{
  /*
    adapted from that: http://www.geekhideout.com/urlcode.shtml
    thanks to the author....
  */

  char t1, t2;

  std::string decode;
  size_t s = strlen(url);

  for(unsigned i = 0; i < s; i++) {
    if(url[i] == '%') {
      if(url[i+1] && url[i+2]) {
        t1 = isdigit(url[i+1]) ? url[i+1]-'0' : tolower(url[i+1])-'a'+10;
        t2 = isdigit(url[i+2]) ? url[i+2]-'0' : tolower(url[i+2])-'a'+10;
        decode.append(1, t1 << 4 | t2);
        i += 2;
      }
    } else {
      decode.append(1, url[i]);
    }
  }

  return decode;
}

/*
  function to check if string appear as valid url
*/
bool GME_NetwIsUrl(const char* str)
{
  bool res = true;
  URL_COMPONENTS urlComponents;
  memset(&urlComponents, 0, sizeof(urlComponents));
  urlComponents.dwStructSize = sizeof(urlComponents);
  urlComponents.dwUserNameLength = 1;
  urlComponents.dwPasswordLength = 1;
  urlComponents.dwHostNameLength = 1;
  urlComponents.dwUrlPathLength = 1;


  int sz = strlen(str) + 1;
  wchar_t *lpwurl = new wchar_t[sz];
  mbstowcs(lpwurl, str, sz);

  if (!WinHttpCrackUrl(lpwurl, 0, 0, &urlComponents))
  {
    res = false;
  }
  delete[] lpwurl;
  return res;
}


class CQuickStringWrap
{
  LPWSTR _szAlloc;

public:
  CQuickStringWrap()
  {
    _szAlloc = NULL;
  }

  ~CQuickStringWrap()
  {
    if (_szAlloc != NULL)
      delete[] _szAlloc;
  }

  operator LPCWSTR() const { return _szAlloc; }

  BOOL Set(LPCWSTR szIn, DWORD dwLen)
  {
    LPWSTR szNew;

    szNew = new WCHAR[dwLen + 1];

    if (szNew == NULL)
    {
      SetLastError(ERROR_OUTOFMEMORY);
      return FALSE;
    }

    memcpy(szNew, szIn, dwLen * sizeof(WCHAR));
    szNew[dwLen] = L'\0';

    if (_szAlloc != NULL)
      delete[] _szAlloc;

    _szAlloc = szNew;

    return TRUE;
  }
};

/*
  function to send GET Http request to a server.
*/
int GME_NetwHttpGET(const char* url_str, const GME_NetwGETOnErr on_err, const GME_NetwGETOnDnl on_dnl, const GME_NetwGETOnEnd on_end)
{
  static const int buf_size = 4096;
  int retval = 0;
  URL_COMPONENTS urlComponents;
  CQuickStringWrap strTargetServer;
  CQuickStringWrap strTargetPath;
  CQuickStringWrap strTargetUsername;
  CQuickStringWrap strTargetPassword;
  HINTERNET hSession = NULL;
  HINTERNET hConnect = NULL;
  HINTERNET hRequest = NULL;
  DWORD statuscode;
  DWORD hbufsize;
  unsigned long long content_length;
  clock_t t; /* start clock for download speed */
  std::vector<char> body_data;
  DWORD dwSize = 0;
  DWORD dwDownloaded = 0;
  DWORD body_size = 0;
  char *pszOutBuffer = NULL;


  memset(&urlComponents, 0, sizeof(urlComponents));
  urlComponents.dwStructSize = sizeof(urlComponents);
  urlComponents.dwUserNameLength = 1;
  urlComponents.dwPasswordLength = 1;
  urlComponents.dwHostNameLength = 1;
  urlComponents.dwUrlPathLength = 1;
  

  int sz = strlen(url_str) + 1;
  wchar_t *lpwurl = new wchar_t[sz];
  mbstowcs(lpwurl, url_str, sz);

  if (!WinHttpCrackUrl(lpwurl, 0, 0, &urlComponents))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to parse URL", url_str);
    return GME_HTTPGET_ERR_DNS;
  }
  

  if (!strTargetServer.Set(urlComponents.lpszHostName, urlComponents.dwHostNameLength)
    || !strTargetPath.Set(urlComponents.lpszUrlPath, urlComponents.dwUrlPathLength))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to set URL fields", url_str);
  return GME_HTTPGET_ERR_DNS;
  }

  if (urlComponents.dwUserNameLength != 0
    && !strTargetUsername.Set(urlComponents.lpszUserName, urlComponents.dwUserNameLength))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to set UserName field", url_str);
    return GME_HTTPGET_ERR_DNS;
  }

  if (urlComponents.dwPasswordLength != 0
    && !strTargetPassword.Set(urlComponents.lpszPassword, urlComponents.dwPasswordLength))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to set Password field", url_str);
    return GME_HTTPGET_ERR_DNS;
  }


  GME_Logs(GME_LOG_NOTICE, "GME_NetwHttpGET", "Connecting to host", url_str);
  hSession = WinHttpOpen(L"OVGME", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
  if (hSession == NULL)
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to open session", url_str);
    retval = GME_HTTPGET_ERR_CNX;
    goto _out;

  }

  hConnect = WinHttpConnect(hSession, strTargetServer, urlComponents.nPort, 0);
  if (hConnect == NULL)
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to open connection", url_str);
    retval = GME_HTTPGET_ERR_CNX;
    goto _out;
  }

  
  hRequest = WinHttpOpenRequest(hConnect, L"GET", strTargetPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
    urlComponents.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);

  BOOL bDone;
  bDone = FALSE;
  if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in sending request", url_str);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }
  
  // End the request.
  if (!WinHttpReceiveResponse(hRequest, NULL))
  {
    DWORD le = GetLastError();
    char errstr[16];
    snprintf(errstr, sizeof(errstr), "%u", le);
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in sending request", errstr);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }

  wchar_t hbuf[256];

  statuscode = 0;
  hbufsize = sizeof(statuscode);
  if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_HEADER_NAME_BY_INDEX, &statuscode,
    &hbufsize, WINHTTP_NO_HEADER_INDEX))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in reading request status", url_str);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }

  switch (statuscode)
  {
  case HTTP_STATUS_REDIRECT:
  {
    hbufsize = sizeof(hbuf);
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_LOCATION,
      WINHTTP_HEADER_NAME_BY_INDEX, &statuscode,
      &hbufsize, WINHTTP_NO_HEADER_INDEX))
    {
      GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in reading redirect location", url_str);
      retval = GME_HTTPGET_ERR_REC;
      goto _out;
    }
    int sz = wcslen(hbuf) + 1;
    char *newurl = new char[sz];
    wcstombs(newurl, hbuf, sz);
    retval = GME_NetwHttpGET(newurl, on_err, on_dnl, on_end);
    delete[] newurl;
    goto _out;
  }

  case HTTP_STATUS_OK:
  case HTTP_STATUS_PARTIAL_CONTENT:
    break;

  default:
  {
    char errstr[16];
    snprintf(errstr, sizeof(errstr), "%x", statuscode);
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", " HTTP Error", errstr);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }

  }

  hbufsize = sizeof(hbuf);
  if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH,
    WINHTTP_HEADER_NAME_BY_INDEX, hbuf,
    &hbufsize, WINHTTP_NO_HEADER_INDEX))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in reading hedaers", url_str);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }
  content_length = _wcstoui64(hbuf, NULL, 10);

  GME_Logs(GME_LOG_NOTICE, "GME_NetwHttpGET", "Body download", url_str);
  
  t = clock(); /* start clock for download speed */
  dwSize = 0;
  dwDownloaded = 0;
  body_size = 0;
  pszOutBuffer = new char[buf_size];
  if (!pszOutBuffer)
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Out of memory", url_str);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }

  do {
    if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
    {
      DWORD le = GetLastError();
      char errstr[16];
      snprintf(errstr, sizeof(errstr), "%u", le);
      GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in query data", errstr);
      retval = GME_HTTPGET_ERR_REC;
      goto _out;
    }

	if (dwSize > 0)
	{
      if (dwSize > buf_size)
        dwSize = buf_size;

      body_size += dwSize;
      if (on_dnl) {
        int pct = (int)(100LL * body_size / content_length);
        clock_t deltat = clock() - t;
        if (deltat == 0)
          deltat = 1;
        int bps = (long long)CLOCKS_PER_SEC * body_size / deltat;
        if (!on_dnl(pct, bps)) {
          GME_Logs(GME_LOG_NOTICE, "GME_NetwHttpGET", "Body download", "Canceled by user");
          retval = 0; // cancelled
          goto _out;
        }
      }

      if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
      {
        GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in reading data", url_str);
        retval = GME_HTTPGET_ERR_REC;
        goto _out;
      }

      body_data.insert(body_data.end(), pszOutBuffer, pszOutBuffer + dwSize);
    }
  } while (dwSize > 0);
  delete[] pszOutBuffer;
  WinHttpCloseHandle(hRequest);
  WinHttpCloseHandle(hConnect);
  WinHttpCloseHandle(hSession);
  delete[] lpwurl;

  if (on_end) on_end(body_data.data(), body_data.size());

  return 0; // success

_out:
  if (pszOutBuffer != NULL)
    delete[] pszOutBuffer;

  if (hRequest != NULL)
    WinHttpCloseHandle(hRequest);

  if (hConnect != NULL)
    WinHttpCloseHandle(hConnect);

  if (hSession != NULL)
    WinHttpCloseHandle(hSession);

  delete[] lpwurl;

  if (on_err) on_err(url_str);

  return retval;
}



/*
  function to send GET Http request to a server.
*/
int GME_NetwHttpGET(const char* url_str, const GME_NetwGETOnErr on_err, const GME_NetwGETOnDnl on_dnl, const GME_NetwGETOnSav on_sav, const std::wstring& path)
{
  static const int buf_size = 65536;
  int retval = 0;
  URL_COMPONENTS urlComponents;
  CQuickStringWrap strTargetServer;
  CQuickStringWrap strTargetPath;
  CQuickStringWrap strTargetUsername;
  CQuickStringWrap strTargetPassword;
  HINTERNET hSession = NULL;
  HINTERNET hConnect = NULL;
  HINTERNET hRequest = NULL;
  DWORD statuscode;
  DWORD hbufsize;
  unsigned long long content_length;
  clock_t t; /* start clock for download speed */
  DWORD dwSize = 0;
  DWORD dwDownloaded = 0;
  DWORD body_size = 0;
  std::wstring file_path;
  FILE* fp = NULL;
  char *pszOutBuffer = NULL;
  wchar_t *fname = NULL;

  memset(&urlComponents, 0, sizeof(urlComponents));
  urlComponents.dwStructSize = sizeof(urlComponents);
  urlComponents.dwUserNameLength = 1;
  urlComponents.dwPasswordLength = 1;
  urlComponents.dwHostNameLength = 1;
  urlComponents.dwUrlPathLength = 1;


  int sz = strlen(url_str) + 1;
  wchar_t *lpwurl = new wchar_t[sz];
  mbstowcs(lpwurl, url_str, sz);

  if (!WinHttpCrackUrl(lpwurl, 0, 0, &urlComponents))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to parse URL", url_str);
    return GME_HTTPGET_ERR_DNS;
  }

  if (!strTargetServer.Set(urlComponents.lpszHostName, urlComponents.dwHostNameLength)
    || !strTargetPath.Set(urlComponents.lpszUrlPath, urlComponents.dwUrlPathLength))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to set URL fields", url_str);
    return GME_HTTPGET_ERR_DNS;
  }

  if (urlComponents.dwUserNameLength != 0
    && !strTargetUsername.Set(urlComponents.lpszUserName, urlComponents.dwUserNameLength))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to set UserName field", url_str);
    return GME_HTTPGET_ERR_DNS;
  }

  if (urlComponents.dwPasswordLength != 0
    && !strTargetPassword.Set(urlComponents.lpszPassword, urlComponents.dwPasswordLength))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to set Password field", url_str);
    return GME_HTTPGET_ERR_DNS;
  }


  GME_Logs(GME_LOG_NOTICE, "GME_NetwHttpGET", "Connecting to host", url_str);
  hSession = WinHttpOpen(L"OVGME", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
  if (hSession == NULL)
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to open session", url_str);
    retval = GME_HTTPGET_ERR_CNX;
    goto _out;
  }

  hConnect = WinHttpConnect(hSession, strTargetServer, urlComponents.nPort, 0);
  if (hConnect == NULL)
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Unable to open connection", url_str);
    retval = GME_HTTPGET_ERR_CNX;
    goto _out;
  }


  hRequest = WinHttpOpenRequest(hConnect, L"GET", strTargetPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
    urlComponents.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);

  BOOL bDone;
  bDone = FALSE;
  if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in sending request", url_str);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }

  // End the request.
  if (!WinHttpReceiveResponse(hRequest, NULL))
  {
    DWORD le = GetLastError();
    char errstr[16];
    snprintf(errstr, sizeof(errstr), "%u", le);
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in sending request", errstr);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }

  wchar_t hbuf[256];

  statuscode = 0;
  hbufsize = sizeof(statuscode);
  if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_HEADER_NAME_BY_INDEX, &statuscode,
    &hbufsize, WINHTTP_NO_HEADER_INDEX))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in reading request status", url_str);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }

  switch (statuscode)
  {
  case HTTP_STATUS_REDIRECT:
  {
    hbufsize = sizeof(hbuf);
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_LOCATION,
      WINHTTP_HEADER_NAME_BY_INDEX, &statuscode,
      &hbufsize, WINHTTP_NO_HEADER_INDEX))
    {
      GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in reading redirect location", url_str);
      retval = GME_HTTPGET_ERR_REC;
      goto _out;
    }
    int sz = wcslen(hbuf) + 1;
    char *newurl = new char[sz];
    wcstombs(newurl, hbuf, sz);
    retval = GME_NetwHttpGET(newurl, on_err, on_dnl, on_sav, path);
    delete[] newurl;
    goto _out;
  }

  case HTTP_STATUS_OK:
  case HTTP_STATUS_PARTIAL_CONTENT:
    break;

  default:
  {
    char errstr[16];
    snprintf(errstr, sizeof(errstr), "%x", statuscode);
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", " HTTP Error", errstr);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }
  }

  fname = NULL;
  hbufsize = sizeof(hbuf);
  if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_DISPOSITION,
      WINHTTP_HEADER_NAME_BY_INDEX, hbuf,
      &hbufsize, WINHTTP_NO_HEADER_INDEX))
  {
    fname = wcsstr(hbuf, L"filename=\"") + 10;
    if (fname)
    {
      wchar_t *fname_end = wcsstr(fname, L"\"");
      if (!fname_end)
      {
        GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", " Wrong filename in content disposition", url_str);
        retval = GME_HTTPGET_ERR_REC;
        goto _out;
      }
      *fname_end = (wchar_t)0;
    }
  }

  if (fname == NULL)
  {
    wchar_t *fname_end = lpwurl + wcslen(lpwurl);
    fname = fname_end;
    wchar_t *cur = fname;
    while (cur >= lpwurl)
    {
	    if (*cur == L'?') 
		    fname_end = cur;
	    else if (*cur == L'/') 
		    break;
	    fname = cur;
	    cur--;
    }
    *fname_end = (wchar_t)0;
  }

  hbufsize = sizeof(hbuf);
  if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH,
    WINHTTP_HEADER_NAME_BY_INDEX, hbuf,
    &hbufsize, WINHTTP_NO_HEADER_INDEX))
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in reading hedaers", url_str);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }
  content_length = _wcstoui64(hbuf, NULL, 10);

  GME_Logs(GME_LOG_NOTICE, "GME_NetwHttpGET", "Body download", url_str);

  /* open temporary file for writing */
  file_path = path + L"\\";
  file_path += fname;
  file_path += L".down";

  fp = _wfopen(file_path.c_str(), L"w+b");
  if (!fp) {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Body download open error", GME_StrToMbs(file_path).c_str());
    retval = GME_HTTPGET_ERR_FOP;
  goto _out;
  }

  t = clock(); /* start clock for download speed */
  dwSize = 0;
  dwDownloaded = 0;
  body_size = 0;
  pszOutBuffer = new char[buf_size];
  if (!pszOutBuffer)
  {
    GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Out of memory", url_str);
    retval = GME_HTTPGET_ERR_REC;
    goto _out;
  }

  do {
    if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
    {
      DWORD le = GetLastError();
      char errstr[16];
      snprintf(errstr, sizeof(errstr), "%u", le);
      GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in query data", errstr);
      retval = GME_HTTPGET_ERR_REC;
      goto _out;
    }

    if (dwSize > 0)
    {
      if (dwSize > buf_size)
        dwSize = buf_size;

      body_size += dwSize;
      if (on_dnl) {
        int pct = (int)(100LL * body_size / content_length);
        clock_t deltat = clock() - t;
        if (deltat == 0)
          deltat = 1;
        int bps = (long long)CLOCKS_PER_SEC * body_size / deltat;
        if (!on_dnl(pct, bps)) {
          GME_Logs(GME_LOG_NOTICE, "GME_NetwHttpGET", "Body download", "Canceled by user");
          retval = 0; // cancelled
          goto _out;
        }
      }

      if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
      {
        GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Error in reading data", url_str);
        retval = GME_HTTPGET_ERR_REC;
        goto _out;
      }

      int written = fwrite(pszOutBuffer, dwSize, 1, fp);
      if (written != 1) {
        GME_Logs(GME_LOG_ERROR, "GME_NetwHttpGET", "Body download write error", GME_StrToMbs(file_path).c_str());
        retval = GME_HTTPGET_ERR_FWR;
        goto _out;
      }
    }

  } while (dwSize > 0);
  delete[] pszOutBuffer; 
  pszOutBuffer = NULL;

  fclose(fp);
  delete[] pszOutBuffer;
  WinHttpCloseHandle(hRequest);
  WinHttpCloseHandle(hConnect);
  WinHttpCloseHandle(hSession);
  delete[] lpwurl;
  if (on_sav) on_sav(file_path.c_str());

  return 0; // success

_out:
  if (fp != NULL)
    fclose(fp);

  if (pszOutBuffer != NULL)
    delete[] pszOutBuffer;

  if (hRequest != NULL)
    WinHttpCloseHandle(hRequest);

  if (hConnect != NULL)
    WinHttpCloseHandle(hConnect);

  if (hSession != NULL)
    WinHttpCloseHandle(hSession);

  delete[] lpwurl;

  if (on_err) on_err(url_str);

  return retval;
}  
