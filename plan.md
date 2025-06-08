## 1. Hệ thống của mình sẽ bao gồm các thành phần sau
- Web server (Apache - + mod_ssl) (Long - Minh)
- KMS - HashiCorp Vault (Minh)
- Database - Encrypted với AES-GCM (Minh)
![image](https://github.com/user-attachments/assets/1b016ef6-03f6-4146-8059-f23608e63459)

- Client (Long)
---
## 2. Việc kí và xác  minh danh tính
- Server: 
	+ Tạo cặp khóa ECDHE + ECDSA, dùng ECDSA private key để ký message chứa pubkey
	-> Backend server
- Client:
	+ Nhận được server_pubkey_ECDSA, dùng để xác minh chữ ký của server
	-> Client-side JS
 ---
## 3. Trao đổi khóa
- Client & Server - Cùng tính shared_secret = ECDH(private_key, peer_pubkey) 
Phía Server -> trong backend
Phía Client -> viết bằng JavaScript trong trình duyệt (Web Crypto API hỗ trợ ECDH)
---
====> Tóm lại:

### Phía Client (JS chạy trong browser):
- Tạo cặp khóa ECDHE

- Xác minh signature ECDSA từ server

- Tính shared_secret (ECDH)

- Sinh keystream từ shared_secret + chunk_index

- Giải mã chunk → Phát audio

- Gửi ACK chunk đã phát để nhận tiếp
![image](https://github.com/user-attachments/assets/126100b0-89f7-4c5b-a8ac-2c56ef1c319b)


### Phía Server:

- Sinh cặp khóa ECDHE + ký bằng ECDSA

- Tính shared_secret với client pubkey

- Mã hóa từng chunk bằng keystream

- Gửi từng chunk kèm chỉ số

![image](https://github.com/user-attachments/assets/41f0b0b4-010a-48dc-807c-3982ad966b80)

cloudflared tunnel   --url https://127.0.0.1:443   --origin-ca-pool /etc/apache2/ssl/server.crt   --origin-server-name 100.94.229.106   --loglevel info
