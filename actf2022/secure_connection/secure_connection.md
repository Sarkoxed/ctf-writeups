<h2>ACTF 2022</h2> 
<h>SECURE CONNECTION(487 points)</h>
<p>Task Description:</p><p>We leak some packets log in author’s PC and get part of the secureconn software, can you get the flag? (software is buggy, don`t mind it and just get your flag)</p>
<p>Attachments:</p><p>The big client.py and core.py files are in directory. Also there's a log file master.txt, that contains:</p>
<p>=================================</p>
<p>>	01 03 6c 69 fa 95 c5 e6 </p>
<p><	01 03 6c 69 fa 95 c5 e6 </p>
<p>>	08 30 53 47 56 73 62 47 38 67 64 47 68 6c 63 6d</p>
<p>	55 73 49 47 78 76 62 6d 63 67 64 47 6c 74 5a 53</p>
<p>	42 75 62 79 42 7a 5a 57 55 73 49 48 70 79 59 58</p>
<p>	68 34 9e ab 52 </p>
<p><	08 44 </p>
<p>	65 57 56 68 61 43 77 67 53 53 42 68 62 53 42 78</p>
<p>	64 57 6c 30 5a 53 42 69 64 58 4e 35 49 47 31 68</p>
<p>	61 32 6c 75 5a 79 42 42 51 31 52 47 49 47 4e 79</p>
<p>	65 58 42 30 62 79 42 6a 61 47 46 73 62 47 56 75</p>
<p>	5a 32 56 7a </p>
<p>	ab 08 96 </p>
<p>>	08 40 64 32 56 73 62 43 77 67 53 53 42 6a 59 57</p>
<p>	34 67 62 32 5a 6d 5a 58 49 67 65 57 39 31 49 47</p>
<p>	45 67 62 6d 39 30 49 47 4a 68 5a 43 42 7a 61 57</p>
<p>	64 75 61 57 34 67 59 32 68 68 62 47 78 6c 62 6d</p>
<p>	64 6c d1 e8 ac </p>
<p><	08 0c </p>
<p>	63 32 68 76 64 79 42 74 5a 51 3d 3d </p>
<p>	06 eb 3b </p>
<p>>	08 34 62 47 56 30 4a 33 4d 67 5a 6d 6c 79 63 33</p>
<p>	51 67 5a 47 6c 32 5a 53 42 70 62 6e 52 76 49 48</p>
<p>	4e 6c 59 33 56 79 5a 53 42 6a 62 32 35 75 5a 57</p>
<p>	4e 30 61 57 39 75 2a 85 95 </p>
<p>>	81 03 d9 b2 df e9 3b f9 </p>
<p><	81 03 d9 b2 df e9 3b f9 </p>
<p>>	82 10 ec 36 e5 b0 69 55 d9 95 56 7e e5 de 45 07</p>
<p>	37 f8 7d d5 57 </p>
<p><	83 10 68 b3 de d5 b8 40 14 dc f3 fb 75 02 d9 39</p>
<p>	0e 34 a6 bf 63 </p>
<p>>	84 10 9f 51 36 ca cd 9f 2a 53 87 39 4b 7d 0c 1c</p>
<p>	XX XX 58 46 05 </p>
<p><	85 10 XX d6 e4 XX XX 5c XX b7 ba 90 6e 57 05 5a</p>
<p>	8e c8 2d db b8 </p>
<p>>	86 10 4b d2 09 24 f0 c3 cd 30 ba 64 a0 f1 d9 64</p>
<p>	69 1e fa a2 d5 </p>
<p><	87 10 dd 76 51 4f 57 36 81 3a a8 c2 17 8e XX f8</p>
<p>	2d 5b 6f 68 ec </p>
<p>>	88 44 ee 49 1a 84 62 41 16 fb 68 5e 5d 47 14 94</p>
<p>aa 6d 3e ac 7c 53 70 7c 46 50 50 90 7e a2 01 12</p>
<p>	04 06 90 02 5e 92 a6 1d d8 29 1b 50 d0 c1 69 13</p>
<p>	b9 cd 0f f5 29 0e da d9 c2 3d 69 38 46 49 76 5b</p>
<p>	84 7f 15 f2 21 ce 3e 4f b4 </p>
<p><	c8 ff </p>
...
<p>=================================</p>
<p>First of all, I've written a parser for this dump file</p><p>It was not hard, since all the instructions for decomposing were in core.py file</p><p>Here's the result:</p>
<p><b>=======================out===========================</b></p>
<p>1 from, hello, no_enc,  len: 3, data: b'li\xfa', crc: 95c5e6</p>
<p></p>
<p>2 to,   hello, no_enc,  len: 3, data: b'li\xfa', crc: 95c5e6</p>
<p></p>
<p>3 from, data, no_enc,  len: 48, data: <strong>b'Hello there, long time no see, zraxx'</strong>, crc: 9eab52 </p>
<p></p>
<p>4 to,   data, no_enc,  len: 68, data: <strong>b'yeah, I am quite busy making ACTF crypto challenges'</strong>, crc: ab0896 </p>
<p></p>
<p>5 from, data, no_enc,  len: 64, data: <strong>b'well, I can offer you a not bad signin challenge'</strong>, crc: d1e8ac </p>
<p></p>
<p>6 to,   data, no_enc,  len: 12, data: <strong>b'show me'</strong>, crc: 06eb3b </p>
<p></p>
<p>7 from, data, no_enc,  len: 52, data: <strong>b"let's first dive into secure connection"</strong>, crc: 2a8595 </p>
<p></p>
<p>8 from, hello, enc,  len: 3, data: d9b2df, crc: e93bf9 </p>
<p></p>
<p>9 to,   hello, enc,  len: 3, data: d9b2df, crc: e93bf9 </p>
<p></p>
<p>10 from, sc_req, enc,  len: 16, data: ec36e5b06955d995567ee5de450737f8, crc: 7dd557 </p>
<p></p>
<p>11 to,   sc_rsp, enc,  len: 16, data: 68b3ded5b84014dcf3fb7502d9390e34, crc: a6bf63 </p>
<p></p>
<p>12 from, m_confirm, enc,  len: 16, data: 9f5136cacd9f2a5387394b7d0c1cXXXX, crc: 584605 </p>
<p></p>
<p>13 to,   s_confirm, enc,  len: 16, data: XXd6e4XXXX5cXXb7ba906e57055a8ec8, crc: 2ddbb8 </p>
<p></p>
<p>14 from, m_random, enc,  len: 16, data: 4bd20924f0c3cd30ba64a0f1d964691e, crc: faa2d5 </p>
<p></p>
<p>15 to,   s_random, enc,  len: 16, data: dd76514f5736813aa8c2178eXXf82d5b, crc: 6f68ec </p>
<p></p>
<p>16 from, data, enc,  len: 68, data: ee491a84624116fb685e5d471494aa6d3eac7c53707c465050907ea20112040690025e92a61dd8291b50d0c16913b9cd0ff5290edad9c23d69384649765b847f15f221ce, crc: 3e4fb4 </p>
<p></p>
<p>17 to,   data, enc, more_data,  len: 255, data: ea4d61864a515fe478413b4c1294b57a388207145b56224a50916abe01121f1280106fc5a577a83a1d40af897a07a18d0cdf1318f2d2d27e424c55575c20907d2df2478a0519c8170633f1a94db615ac37bba648c133dff426c20a28f9125fe1fd35d0af550701851692626b6ffac7434f92b568c266533652de21864323033898f514fd5cb0ef2059fe9ab68e2917d75d5ccfc6a8c21dba69d73bb79944c38bb5208ffe67e028649a406a2bd71d8670f19fefa719cfdbe672f4c58a1e2d1c092c3f21db23bf63f7da5d78905602f222e458a5ca7a04835d4cd90a1a5d900a78f67516ea443289971a7fe2da157d60ce1b6331acc87ef69ce9589efa9c5469, crc: 10b531 </p>
<p></p>
<p>18 to,   data, enc, more_data,  len: 255, data: 8411de79f3a0cfb304f6dfec305c00ca30d769829e559b428dc6f0ae6d8b73d9afbbbfa8b4f4e5ad6bbe553beb3497882b8a413feee320f63869b79b98ac6a6783e0e5dee5e18e804313e22e56383afdb4eaa54487ad8aec5a5e016e5ddb3944813957e70524e058e85641fa4dcdb2714d6aa479160b4368c8dbadd66d8d8a9e4c8a7f584554f31522823559381e754e8cc8c6a00be26d750d7849366eccb224909dc98bda4e5181153c6707c0f65c9c6da1148cfefdc77a65636917f93c8c0d447ebd7e49894fb4617ab6b3709e2ab3b9c9fe18947eb45085e7b9e72cdbc01092ac603cc2f7cbfbfbb69ff9affaba609b99cf35694b9b9ef4cab3dfbc1d7b, crc: 30a6be </p>
<p></p>
<p>19 to,   data, enc, more_data,  len: 255, data: 4a21065d5ab2a0e2cb4f31e22bddd9576e81cd3105dc91a9fb9db0dcec197be84e441a79ecb41553852f1558785dc31f036208a452c357b1524cf56dbcdf985e6435b8f6174cfd28d92e3d30abe982ee10d80a753155bed89c85bad3649bed2f2e41a53c1a1edd6547227014868235ac5ebbe6e8c7cb92640d0cdd81a69135ad3b3639bee246285cc513cb6d216447342c596d77dfe64a06667b64f4b75ac7c603cb5c02aceaf4f780ec1cc43fed5fb8cf194b029d8e485fff93695f37862102b76060549ea9d0c5f852be7ced74e30dcda4bb9513a957fae08e41aa0974b5b04567f8a49da94c0fc8f2820a457118daece75a4ed45d0db8757c47a9d185e5, crc: 64276a </p>
<p></p>
<p>20 to,   data, enc,  len: 91, data: a6367b6aa555af69a9a97d0e09aa4886d52720c77465e33718768d1489d9d1cc84d0ed7bd60455002e04ee7fae368c478382a2ef264bdd9173d28c29315b8f3e3c19248950bed65fe788e4ac137126851bc88d4794e641859e6fb2, crc: 0b3768 </p>
<p></p>
<p>21 from, data, enc, more_data,  len: 255, data: b729d427d4a9d5952ec3cecc1e70159c27c6638d8a03ed6cf1e4f5b143961ed9a79faee890f5ecad639e4f09ce13cfbc33d84f27c8ea3ace1178a8b18e9f6b5face2e8ebedc48fae7a36d500600a53ea89e8c61a95c5fcd85445711563fe1664d12142ee112af26dcb7340a345d0996a4952b13f1f703d4c99b1b3e902878ff745ac61216b49d838058d0a6837001b11bcc6c48231eb51445f74483558ddbc119ff7b985cb1e69b00b424875e2d04d9665f20185e997bc4872474254e12d99547659b75852ba5e994164b7cf459049f280ffff1db370bd7290edb3c537d6a735fa993e09e8c5debcd5858a98f8f4aa4dc9cece013d6f958fdad787e0993644, crc: de2274 </p>
<p></p>
<p>22 from, data, enc,  len: 29, data: 1013375c5ca983e3905a58f705de88337fb3fc341cdaab9eaecf90ab8b, crc: 8c601f </p>
<p></p>
<p>23 to,   data, enc,  len: 40, data: 18aee95ecac09ee63dd28707b8942d4f2a7052d71bfd27d81bcceffd208a1463f9a135248def5781, crc: eca094 </p>
<p></p>
<p>24 from, data, enc,  len: 96, data: a2162539df5bac459586535812db74a6cb541dd71f64ec4d12719f32a6def899e3d7eb62c4127702173ec242bc32aa5e82fee8ea335bc4ad7dc8f22e2059a30419171abe73afe65bfaa6ada32a15788d0db6b359b0be7fa6af68cde6e24ca95d, crc: 0b4acb </p>
<p></p>
<p>25 to,   data, enc,  len: 8, data: fd81d2b58c5e3206, crc: e78a0e </p>
<p></p>
<p><b>=====================================================</b></p>
<p>You will not find any valuable information in client.py</p>
<p>Now we can draw a few conclusions, based on dump file and core.py file</p>
<p>Obviously the first of them is master and the second is slave</p>
<p>First 7 messages are not interesting. All we get from them is that they are using a secure connection from now on</p>
<p>Messages from 8 to 15 are a handshake between sockets. From which we can get:</p>
<p>8-9: crc seed 0xd9b2df to check that connection was not interrupted by anyone</p>
<p>10: master's IV = ec36e5b06955d995 and Secret = 567ee5de450737f8</p>
<p>11: slave's  IV = 68b3ded5b84014dc and Secret = f3fb7502d9390e34</p>
<p>12: master's confirm = 9f5136cacd9f2a5387394b7d0c1cXXXX (note that we don't know the last two bytes)</p>
<p>13: slave's  confirm = XXd6e4XXXX5cXXb7ba906e57055a8ec8 (now we don't know 4 bytes)</p>
<p>14: master's random_value = 4bd20924f0c3cd30ba64a0f1d964691e</p>
<p>15: slave's  random_value = dd76514f5736813aa8c2178eXXf82d5b(1 byte unknown)</p>
<p>Then they send data to each other in which we are not interested for now</p> 

```python
from Crypto.Cipher import AES
import base64
import libscrc
from multiprocessing import Pool
from time import time
from Crypto.Util.number import long_to_bytes
from copy import copy
```

<p>The key to the solution is the fact that their shared key is very small(it's mod(0x1000000) hence we can iterate over this key</p>

```python
def calc_crc(crc, pdu):
    initvalue = int.from_bytes(crc, "little")
    crc = libscrc.hacker24(data=pdu, poly=0x00065B, init=initvalue,
                            xorout=0x00000000, refin=True, refout=True)
    return crc.to_bytes(3, "little")

def bytes_xor_16(bytes1, bytes2):
    v1 = int.from_bytes(bytes1, 'big')
    v2 = int.from_bytes(bytes2, 'big')
    v3 = v1 ^ v2
    return (v3).to_bytes(16, 'big')

def secure_decrypt_packet(key, plain, nonce):
    aes = AES.new(key=key, mode=AES.MODE_CCM, nonce=nonce)
    return aes.decrypt(plain)

def secure_encrypt(key, plain):
    aes = AES.new(key=key, mode=AES.MODE_ECB)
    return aes.encrypt(plain)

def secure_confirm(key, r, p1, p2):
    return secure_encrypt(key, bytes_xor_16(secure_encrypt(key, bytes_xor_16(r, p1)), p2))
```
<br>

```python
crc_seed = bytes.fromhex('d9b2df')

m_IV =     bytes.fromhex('ec36e5b06955d995')
m_Secret = bytes.fromhex('567ee5de450737f8')
s_IV =     bytes.fromhex('68b3ded5b84014dc')
s_Secret = bytes.fromhex('f3fb7502d9390e34')
m_random = bytes.fromhex('4bd20924f0c3cd30ba64a0f1d964691e')
```

<p>Now let's find out what are the XX unknown values using simple iteration</p>

```python
def get_m_confirm(crc_seed, crc):
    for i in range(256):
        for j in range(256):
            x, y = hex(i)[2:].zfill(2), hex(j)[2:].zfill(2)
            s = bytes.fromhex(f'84109f5136cacd9f2a5387394b7d0c1c{x}{y}')  # note that we use the whole message, 
                                                                          # including first two bytes 0x84 and 0x10 + data
            if(crc == calc_crc(crc_seed, s)):
                return s
m_confirm_crc = bytes.fromhex('584605')
m_confirm = get_m_confirm(crc_seed, m_confirm_crc)[2:]
print(m_confirm)
```

```
b'\x9fQ6\xca\xcd\x9f*S\x879K}\x0c\x1c\x16\xfa'
```

<p>We know that m_confirm = aes(key=shared_key, mode=ECB, plain=plain)</p>
<p>where plain = aes(key=shared_key, mode=ECB, plain=plain1)</p>
<p>plain1 = b'\xff' * 16 <b>XOR</b> aes(key = shared_key, mode=ECB, plain=m_random <b>XOR</b> 0)</p>
<p>Hence we can iterete over [0, 0x1000000] to find the key</p>

```python
def get_key(g):
    for x in g:
        x = x.to_bytes(16, "little")
        if secure_confirm(x, m_random, b"\x00"*16, b"\xff"*16) == m_confirm:
            print(f"shared key = {x}")
gs = [range(i, 256**3, 32) for i in range(32)]
with Pool(10) as pool:
    pool.map(get_key, gs)
```

```
shared key = b'%=\x8c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

```python
shared_key = b'%=\x8c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
assert m_confirm == secure_confirm(shared_key, m_random, b"\x00"*16, b"\xff"*16)
```

<p>The rest is quite clear: we have to find s_random to calculate:</p>
<p>storekey = secure_encrypt(numeric_key, m_random[:8] + s_random[8:])</p>
<p>And then</p>
<p>sessionkey = secure_encrypt(storekey, m_secret + s_secret)
<p>Finding s_random is very easy, since we have already done it with m_confrim.</p>

```python
def get_s_random(crc_seed, crc):
    for i in range(256):
        x = hex(i)[2:].zfill(2)
        s = bytes.fromhex(f'8710dd76514f5736813aa8c2178e{x}f82d5b')  # note that we use the whole message, 
                                                                     # including first two bytes 0x87 and 0x10 + data
        if(crc == calc_crc(crc_seed, s)):
            return s
s_random_crc = bytes.fromhex('6f68ec')
s_random = get_s_random(crc_seed, s_random_crc)[2:]
```

<p>We could also calculate s_confirm, but this is only necessary for verification, and there are many values that correspond to crc = '2ddbb8'.It is not surprising, since we have to iterate over 3 unknown bytes.</p>

```python
store_key = secure_encrypt(shared_key, m_random[:8] + s_random[8:])
sessionkey = secure_encrypt(store_key, m_Secret + s_Secret)
```
<br>

```python
known_ciphertexts = [
    "ee491a84624116fb685e5d471494aa6d3eac7c53707c465050907ea20112040690025e92a61dd8291b50d0c16913b9cd0ff5290edad9c23d69384649765b847f15f221ce",
    "ea4d61864a515fe478413b4c1294b57a388207145b56224a50916abe01121f1280106fc5a577a83a1d40af897a07a18d0cdf1318f2d2d27e424c55575c20907d2df2478a0519c8170633f1a94db615ac37bba648c133dff426c20a28f9125fe1fd35d0af550701851692626b6ffac7434f92b568c266533652de21864323033898f514fd5cb0ef2059fe9ab68e2917d75d5ccfc6a8c21dba69d73bb79944c38bb5208ffe67e028649a406a2bd71d8670f19fefa719cfdbe672f4c58a1e2d1c092c3f21db23bf63f7da5d78905602f222e458a5ca7a04835d4cd90a1a5d900a78f67516ea443289971a7fe2da157d60ce1b6331acc87ef69ce9589efa9c5469",
    "8411de79f3a0cfb304f6dfec305c00ca30d769829e559b428dc6f0ae6d8b73d9afbbbfa8b4f4e5ad6bbe553beb3497882b8a413feee320f63869b79b98ac6a6783e0e5dee5e18e804313e22e56383afdb4eaa54487ad8aec5a5e016e5ddb3944813957e70524e058e85641fa4dcdb2714d6aa479160b4368c8dbadd66d8d8a9e4c8a7f584554f31522823559381e754e8cc8c6a00be26d750d7849366eccb224909dc98bda4e5181153c6707c0f65c9c6da1148cfefdc77a65636917f93c8c0d447ebd7e49894fb4617ab6b3709e2ab3b9c9fe18947eb45085e7b9e72cdbc01092ac603cc2f7cbfbfbb69ff9affaba609b99cf35694b9b9ef4cab3dfbc1d7b",
    "4a21065d5ab2a0e2cb4f31e22bddd9576e81cd3105dc91a9fb9db0dcec197be84e441a79ecb41553852f1558785dc31f036208a452c357b1524cf56dbcdf985e6435b8f6174cfd28d92e3d30abe982ee10d80a753155bed89c85bad3649bed2f2e41a53c1a1edd6547227014868235ac5ebbe6e8c7cb92640d0cdd81a69135ad3b3639bee246285cc513cb6d216447342c596d77dfe64a06667b64f4b75ac7c603cb5c02aceaf4f780ec1cc43fed5fb8cf194b029d8e485fff93695f37862102b76060549ea9d0c5f852be7ced74e30dcda4bb9513a957fae08e41aa0974b5b04567f8a49da94c0fc8f2820a457118daece75a4ed45d0db8757c47a9d185e5",
    "a6367b6aa555af69a9a97d0e09aa4886d52720c77465e33718768d1489d9d1cc84d0ed7bd60455002e04ee7fae368c478382a2ef264bdd9173d28c29315b8f3e3c19248950bed65fe788e4ac137126851bc88d4794e641859e6fb2",
    "b729d427d4a9d5952ec3cecc1e70159c27c6638d8a03ed6cf1e4f5b143961ed9a79faee890f5ecad639e4f09ce13cfbc33d84f27c8ea3ace1178a8b18e9f6b5face2e8ebedc48fae7a36d500600a53ea89e8c61a95c5fcd85445711563fe1664d12142ee112af26dcb7340a345d0996a4952b13f1f703d4c99b1b3e902878ff745ac61216b49d838058d0a6837001b11bcc6c48231eb51445f74483558ddbc119ff7b985cb1e69b00b424875e2d04d9665f20185e997bc4872474254e12d99547659b75852ba5e994164b7cf459049f280ffff1db370bd7290edb3c537d6a735fa993e09e8c5debcd5858a98f8f4aa4dc9cece013d6f958fdad787e0993644",
    "1013375c5ca983e3905a58f705de88337fb3fc341cdaab9eaecf90ab8b",
    "18aee95ecac09ee63dd28707b8942d4f2a7052d71bfd27d81bcceffd208a1463f9a135248def5781",
    "a2162539df5bac459586535812db74a6cb541dd71f64ec4d12719f32a6def899e3d7eb62c4127702173ec242bc32aa5e82fee8ea335bc4ad7dc8f22e2059a30419171abe73afe65bfaa6ada32a15788d0db6b359b0be7fa6af68cde6e24ca95d",
    "fd81d2b58c5e3206"]
```

<p>Well, you can just count the number of messages sent by each side or iterate over [0, 10] to get a one-time number for aes encryption.</p>

```python
for cip in known_ciphertexts:
    for n in range(10):
        try:
            pl = base64.b64decode(secure_decrypt_packet(sessionkey, bytes.fromhex(cip), n.to_bytes(13, "little")) + b'====')
            if(pl.decode()):
                print(pl, n)
        except Exception as e:
            continue
```

```
b'I will tell you my flag after you finish your poem' 4
b"You mean this one? Shall I compare thee to a summer's day? Thou art more lovely and more temperate: Rough winds do shake the darling buds of May, And summer's lease hath all too short a date:" 4
b'No I mean this one, I never saw a Moor-I never saw the Sea-Yet know I how the Heather looksAnd what a Billow be.I never spoke with GodNor visited in Heaven-Yet certain am I of the spotAs if t' 5
b'q;cM8' 1
b'Nevermind, long live the AAA' 8
b'You got your flag: ACTF{ShORt_NUmeR1c_KEY_1s_Vuln3R4bLe_TO_e@V3sDropPEr}' 7
b'\x07' 7
b'\x06' 8
b'Cool' 9
```





