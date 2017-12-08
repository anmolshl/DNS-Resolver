Note:

CNAME related queries run slowly (5, sometimes up to 20 secs)
Possibly due to incomplete cache usage (i.e. it could be used to
lookup name servers that could be used, or also immediately check for
CNAMEs before the initial query, etc)