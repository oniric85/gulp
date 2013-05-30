# TODO
- automatic iteration through multiple rows
- time-based: dynamically changing the required time for TRUE and FALSE requests to balance changes in the server workload
- character range prediction ( maybe )
- config file support

# Known Issues/Behaviour
- Doesn't support HTTPS
- You can't specify empty POST parameters.
- You can't use the characters "&" or "=" in your request content ( query parameter ) if you use POST method, you must urlencode them FIRST.
- When redirecting the received Set-Cookie header is used to set a Cookie header.