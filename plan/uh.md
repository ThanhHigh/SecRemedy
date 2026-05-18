[
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "delete",
    "directive": "listen",
    "args": [],
    "block": [],
    "line": 105,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 5, "block", 3]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "delete",
    "directive": "listen",
    "args": [],
    "block": [],
    "line": 103,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 5, "block", 1]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "error_page",
    "args": ["404", "/custom_404.html"],
    "block": [],
    "line": 101,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 5, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "error_page",
    "args": ["500", "502", "503", "504", "/custom_50x.html"],
    "block": [],
    "line": 101,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 5, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "location",
    "args": ["^~", "/.well-known/acme-challenge/"],
    "block": [
      {"directive": "allow", "args": ["all"]},
      {"directive": "default_type", "args": ["text/plain"]}
    ],
    "line": 101,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 5, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "location",
    "args": ["~", "/\\."],
    "block": [
      {"directive": "deny", "args": ["all"]},
      {"directive": "return", "args": ["404"]}
    ],
    "line": 101,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 5, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "return",
    "args": ["301", "https://$host$request_uri"],
    "block": [],
    "line": 101,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 5, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "add_header",
    "args": ["X-Content-Type-Options", "\"nosniff\"", "always"],
    "block": [],
    "line": 0,
    "logical_context": ["http", "server"],
    "exact_path": ["config", 2, "parsed", 5, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "add_header",
    "args": ["Content-Security-Policy", "\"default-src 'self'; frame-ancestors 'self'; form-action 'self';\"", "always"],
    "block": [],
    "line": 0,
    "logical_context": ["http", "server"],
    "exact_path": ["config", 2, "parsed", 5, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "delete",
    "directive": "listen",
    "args": [],
    "block": [],
    "line": 93,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 4, "block", 3]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "delete",
    "directive": "listen",
    "args": [],
    "block": [],
    "line": 91,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 4, "block", 1]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "error_page",
    "args": ["404", "/custom_404.html"],
    "block": [],
    "line": 89,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 4, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "error_page",
    "args": ["500", "502", "503", "504", "/custom_50x.html"],
    "block": [],
    "line": 89,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 4, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "location",
    "args": ["^~", "/.well-known/acme-challenge/"],
    "block": [
      {"directive": "allow", "args": ["all"]},
      {"directive": "default_type", "args": ["text/plain"]}
    ],
    "line": 89,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 4, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "location",
    "args": ["~", "/\\."],
    "block": [
      {"directive": "deny", "args": ["all"]},
      {"directive": "return", "args": ["404"]}
    ],
    "line": 89,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 4, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "return",
    "args": ["301", "https://$host$request_uri"],
    "block": [],
    "line": 89,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 4, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "add_header",
    "args": ["X-Content-Type-Options", "\"nosniff\"", "always"],
    "block": [],
    "line": 0,
    "logical_context": ["http", "server"],
    "exact_path": ["config", 2, "parsed", 4, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "add_header",
    "args": ["Content-Security-Policy", "\"default-src 'self'; frame-ancestors 'self'; form-action 'self';\"", "always"],
    "block": [],
    "line": 0,
    "logical_context": ["http", "server"],
    "exact_path": ["config", 2, "parsed", 4, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "error_page",
    "args": ["404", "/custom_404.html"],
    "block": [],
    "line": 76,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 3, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "error_page",
    "args": ["500", "502", "503", "504", "/custom_50x.html"],
    "block": [],
    "line": 76,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 3, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "location",
    "args": ["^~", "/.well-known/acme-challenge/"],
    "block": [
      {"directive": "allow", "args": ["all"]},
      {"directive": "default_type", "args": ["text/plain"]}
    ],
    "line": 76,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 3, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "location",
    "args": ["~", "/\\."],
    "block": [
      {"directive": "deny", "args": ["all"]},
      {"directive": "return", "args": ["404"]}
    ],
    "line": 76,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 3, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "add_header",
    "args": ["X-Content-Type-Options", "\"nosniff\"", "always"],
    "block": [],
    "line": 0,
    "logical_context": ["http", "server"],
    "exact_path": ["config", 2, "parsed", 3, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "add_header",
    "args": ["Content-Security-Policy", "\"default-src 'self'; frame-ancestors 'self'; form-action 'self';\"", "always"],
    "block": [],
    "line": 0,
    "logical_context": ["http", "server"],
    "exact_path": ["config", 2, "parsed", 3, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "add_header",
    "args": ["X-Content-Type-Options", "\"nosniff\"", "always"],
    "block": [],
    "line": 0,
    "logical_context": ["http", "server", "location"],
    "exact_path": ["config", 2, "parsed", 2, "block", 13, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "add_header",
    "args": ["Content-Security-Policy", "\"default-src 'self'; frame-ancestors 'self'; form-action 'self';\"", "always"],
    "block": [],
    "line": 0,
    "logical_context": ["http", "server", "location"],
    "exact_path": ["config", 2, "parsed", 2, "block", 13, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "add_header",
    "args": ["X-Content-Type-Options", "\"nosniff\"", "always"],
    "block": [],
    "line": 0,
    "logical_context": ["http", "server", "location"],
    "exact_path": ["config", 2, "parsed", 2, "block", 12, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "add_header",
    "args": ["Content-Security-Policy", "\"default-src 'self'; frame-ancestors 'self'; form-action 'self';\"", "always"],
    "block": [],
    "line": 0,
    "logical_context": ["http", "server", "location"],
    "exact_path": ["config", 2, "parsed", 2, "block", 12, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "delete",
    "directive": "access_log",
    "args": [],
    "block": [],
    "line": 53,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 2, "block", 6]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "error_page",
    "args": ["404", "/custom_404.html"],
    "block": [],
    "line": 41,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 2, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "error_page",
    "args": ["500", "502", "503", "504", "/custom_50x.html"],
    "block": [],
    "line": 41,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 2, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "location",
    "args": ["^~", "/.well-known/acme-challenge/"],
    "block": [
      {"directive": "allow", "args": ["all"]},
      {"directive": "default_type", "args": ["text/plain"]}
    ],
    "line": 41,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 2, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "location",
    "args": ["~", "/\\."],
    "block": [
      {"directive": "deny", "args": ["all"]},
      {"directive": "return", "args": ["404"]}
    ],
    "line": 41,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 2, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "error_page",
    "args": ["404", "/custom_404.html"],
    "block": [],
    "line": 6,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 1, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "error_page",
    "args": ["500", "502", "503", "504", "/custom_50x.html"],
    "block": [],
    "line": 6,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 1, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "location",
    "args": ["^~", "/.well-known/acme-challenge/"],
    "block": [
      {"directive": "allow", "args": ["all"]},
      {"directive": "default_type", "args": ["text/plain"]}
    ],
    "line": 6,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 1, "block"]
  },
  {
    "file": "/etc/nginx/sites-available/magento.example.com.conf",
    "action": "add",
    "directive": "location",
    "args": ["~", "/\\."],
    "block": [
      {"directive": "deny", "args": ["all"]},
      {"directive": "return", "args": ["404"]}
    ],
    "line": 6,
    "logical_context": ["server"],
    "exact_path": ["config", 2, "parsed", 1, "block"]
  }
]