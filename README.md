# DVWA Command Injection Protection with ModSecurity WAF

## 1. Giới thiệu dự án

Dự án thực hành xây dựng và đánh giá cơ chế bảo vệ ứng dụng web trước lỗ hổng Command Injection bằng Web Application Firewall (WAF), sử dụng Nginx kết hợp với ModSecurity trên Ubuntu Linux.

Ứng dụng DVWA (Damn Vulnerable Web Application) được sử dụng làm môi trường kiểm thử. Dự án tập trung vào việc xây dựng Custom Rule để phát hiện dấu hiệu chèn lệnh hệ thống, so sánh chế độ giám sát `DetectionOnly` với chế độ chặn `On`, đồng thời khảo sát khả năng phát hiện của OWASP Core Rule Set (CRS).

Toàn bộ hoạt động kiểm thử được thực hiện trong môi trường lab phục vụ mục đích học tập và nghiên cứu an toàn thông tin.

## 2. Mục tiêu

* Tìm hiểu kiến trúc triển khai Nginx kết hợp ModSecurity để bảo vệ ứng dụng web.
* Tái hiện và quan sát lỗ hổng Command Injection trong DVWA.
* Xây dựng Custom Rule với ID `10001` để phát hiện các ký tự có thể liên quan đến việc nối hoặc nội suy lệnh shell.
* Phân biệt hoạt động ghi nhận cảnh báo trong chế độ `DetectionOnly` và hành động từ chối request trong chế độ `On`.
* Phân tích audit log và các sự kiện bảo mật do ModSecurity ghi nhận.
* Kiểm thử OWASP CRS để tìm hiểu cơ chế phát hiện Remote Command Execution (RCE) và chấm điểm bất thường.

## 3. Công nghệ sử dụng

| Thành phần                  | Công nghệ                        |
| --------------------------- | -------------------------------- |
| Hệ điều hành                | Ubuntu Linux chạy trên máy ảo    |
| Web server và reverse proxy | Nginx                            |
| Web Application Firewall    | ModSecurity                      |
| Ứng dụng kiểm thử           | DVWA                             |
| Bộ quy tắc bảo mật          | Custom Rule và OWASP CRS         |
| Kỹ thuật kiểm thử           | Command Injection                |
| Phân tích sự kiện           | ModSecurity log và HTTP response |

Các phiên bản phần mềm và đường dẫn cấu hình cụ thể cần được đối chiếu với môi trường triển khai thực tế trước khi sử dụng README này làm hướng dẫn tái hiện.

## 4. Kiến trúc hệ thống

```text
+--------------------+
|   Client/Browser   |
+--------------------+
          |
          | HTTP Request
          v
+-----------------------------+
| Nginx + ModSecurity WAF     |
| - Custom Rule               |
| - OWASP CRS (khi bật)       |
+-----------------------------+
          |
          | Request hợp lệ
          v
+-----------------------------+
| DVWA - Command Injection    |
+-----------------------------+
          |
          v
+-----------------------------+
| HTTP Response / WAF Logs    |
+-----------------------------+
```

Nginx tiếp nhận HTTP request và chuyển request qua lớp kiểm tra của ModSecurity. Các rule được cấu hình sẽ đánh giá tham số đầu vào để tìm dấu hiệu tấn công.

Tùy theo chế độ vận hành và hành động của rule, ModSecurity có thể ghi nhận cảnh báo hoặc từ chối request trước khi request được chuyển đến ứng dụng DVWA.

## 5. Cấu trúc repository

```text
dvwa-command-injection-modsecurity/
├── README.md
├── report/
│   └── Bao_cao_Command_Injection_DVWA.pdf
└── modsecurity/
    └── command-injection.conf
```

| Tệp                                         | Mô tả                                                               |
| ------------------------------------------- | ------------------------------------------------------------------- |
| `README.md`                                 | Giới thiệu dự án, kiến trúc, quy trình kiểm thử và kết quả          |
| `report/Bao_cao_Command_Injection_DVWA.pdf` | Báo cáo thực nghiệm chi tiết, bao gồm ảnh chụp và phân tích kết quả |
| `modsecurity/command-injection.conf`        | Custom Rule được tách riêng để tham khảo và nghiên cứu              |

Các đường dẫn trong bảng phải khớp với tên tệp thực tế trong repository. Nếu tệp báo cáo hoặc rule có tên khác, cần cập nhật lại đường dẫn tương ứng.

## 6. Custom Rule phát hiện Command Injection

Custom Rule được xây dựng để kiểm tra tham số request và tìm kiếm các ký tự thường xuất hiện trong biểu thức nối lệnh hoặc nội suy lệnh shell.

Rule được sử dụng trong thực nghiệm có ID `10001`, thông báo `Command Injection Detected` và nhãn `WEB_ATTACK/COMMAND_INJECTION`.

Ví dụ về biểu thức chính quy dùng để phát hiện các ký tự đáng chú ý:

```regex
(;|\||&|`|\$\()
```

Biểu thức trên nhận diện một số ký tự hoặc chuỗi ký tự như dấu chấm phẩy, pipe, ampersand, backtick và phần mở đầu của cú pháp nội suy `$(`. Đây là các dấu hiệu cần kiểm tra thêm, không phải bằng chứng chắc chắn rằng mọi request chứa những ký tự này đều là tấn công.

### Ý nghĩa các thành phần chính

| Thành phần     | Ý nghĩa                                                               |
| -------------- | --------------------------------------------------------------------- |
| `SecRule ARGS` | Kiểm tra các tham số request mà ModSecurity đưa vào collection `ARGS` |
| `@rx`          | Sử dụng biểu thức chính quy để so khớp dữ liệu                        |
| `id:10001`     | Định danh của Custom Rule                                             |
| `phase:2`      | Thực thi ở giai đoạn xử lý request body                               |
| `deny`         | Từ chối request khi rule khớp và chế độ vận hành cho phép chặn        |
| `status:403`   | Chỉ định mã phản hồi HTTP 403 khi thực hiện hành động từ chối         |
| `msg`          | Nội dung thông báo trong log                                          |
| `tag`          | Nhãn phân loại sự kiện bảo mật                                        |

**Lưu ý:** Biểu thức chính quy trên chỉ là phần minh họa điều kiện phát hiện. Khi triển khai thực tế, cần sử dụng nguyên văn rule đã được kiểm thử và xác nhận cú pháp theo phiên bản ModSecurity đang sử dụng. Không thay thế cấu hình đang hoạt động bằng đoạn minh họa này nếu chưa kiểm thử.

## 7. Quy trình kiểm thử

### 7.1. Giai đoạn 1: Kiểm thử khi tắt ModSecurity

**Mục tiêu:** Quan sát hành vi của DVWA khi không có cơ chế kiểm tra request của ModSecurity.

* Đặt `SecRuleEngine Off` trong môi trường lab.
* Truy cập chức năng Command Injection của DVWA.
* Gửi dữ liệu kiểm thử có dấu hiệu nối lệnh, chẳng hạn `127.0.0.1 && id`.
* Quan sát phản hồi trên giao diện và xác minh kết quả thực tế.

Trong lần kiểm thử được mô tả trong báo cáo, ứng dụng trả về kết quả thực thi lệnh `id` dưới quyền tài khoản dịch vụ web. Nếu kết quả này được xác nhận bằng ảnh chụp hoặc đầu ra thực nghiệm, đây là bằng chứng cho thấy đầu vào có thể dẫn đến thực thi lệnh hệ thống trong cấu hình đang kiểm thử.

### 7.2. Giai đoạn 2: Chế độ DetectionOnly

**Mục tiêu:** Xác minh khả năng phát hiện và ghi log mà không chủ động chặn request bằng ModSecurity.

* Đặt `SecRuleEngine DetectionOnly`.
* Bật Custom Rule ID `10001`.
* Gửi lại request kiểm thử.
* Quan sát phản hồi HTTP và log ModSecurity.

Log thực nghiệm ghi nhận thông báo:

```text
ModSecurity: Warning
[msg "Command Injection Detected"]
[id "10001"]
[tag "WEB_ATTACK/COMMAND_INJECTION"]
[uri "/vulnerabilities/exec/"]
```

Kết quả này cho thấy rule đã phát hiện mẫu dữ liệu đáng ngờ và ghi nhận cảnh báo. Trong chế độ `DetectionOnly`, ModSecurity không chủ động chặn request theo hành động disruptive của rule; ứng dụng vẫn có thể xử lý request.

Cần kiểm tra phản hồi của DVWA để xác nhận hành vi thực tế, thay vì chỉ dựa vào sự xuất hiện của cảnh báo.

### 7.3. Giai đoạn 3: Chế độ chặn với Custom Rule

**Mục tiêu:** Kiểm tra khả năng từ chối request khi ModSecurity được bật ở chế độ chặn.

* Đặt `SecRuleEngine On`.
* Giữ Custom Rule ID `10001` trong cấu hình đang kiểm thử.
* Kiểm tra cú pháp cấu hình Nginx trước khi áp dụng thay đổi.
* Gửi lại request thử nghiệm.
* Đối chiếu mã HTTP và log ModSecurity.

Kết quả thực nghiệm được ghi nhận:

```text
HTTP/1.1 403
```

Log ModSecurity có thông báo:

```text
ModSecurity: Access denied with code 403 (phase 2)
[id "10001"]
[msg "Command Injection Detected"]
[tag "WEB_ATTACK/COMMAND_INJECTION"]
[uri "/vulnerabilities/exec/"]
```

Hai dấu hiệu này cho thấy request thử nghiệm đã bị từ chối bởi cơ chế bảo vệ. Để khẳng định lệnh hệ thống không được thực thi, cần đối chiếu thêm kết quả ở ứng dụng và xác nhận request bị chặn trước khi được chuyển đến DVWA.

### 7.4. Giai đoạn 4: Kiểm thử OWASP Core Rule Set

**Mục tiêu:** Khảo sát khả năng phát hiện của OWASP CRS khi kiểm thử độc lập với Custom Rule.

Theo kết quả được mô tả trong báo cáo, request chứa cú pháp nội suy shell `$(id)` đã kích hoạt các rule thuộc nhóm phát hiện Remote Command Execution và cơ chế đánh giá tổng điểm bất thường.

Các rule được báo cáo ghi nhận gồm:

| Rule ID  | Vai trò                                                                                |
| -------- | -------------------------------------------------------------------------------------- |
| `932130` | Phát hiện biểu thức liên quan đến Unix shell trong nhóm rule RCE                       |
| `949110` | Đánh giá tổng điểm bất thường đầu vào và thực hiện cơ chế chặn khi đạt ngưỡng cấu hình |

Kết quả thực nghiệm được mô tả là HTTP 403. Cần giữ lại log tương ứng để xác nhận rule thực sự được kích hoạt và tổng điểm bất thường đạt ngưỡng nào trong cấu hình CRS đang sử dụng.

OWASP CRS sử dụng nhiều rule kết hợp để phát hiện các dạng request đáng ngờ. Việc một rule phát hiện dấu hiệu tấn công và việc cơ chế đánh giá quyết định chặn request là hai bước khác nhau.

## 8. Bảng so sánh kết quả

| Chế độ                 | Cấu hình                               | Hành vi ghi nhận                                 | Kết quả HTTP được báo cáo           | Ý nghĩa                                         |
| ---------------------- | -------------------------------------- | ------------------------------------------------ | ----------------------------------- | ----------------------------------------------- |
| Off                    | `SecRuleEngine Off`                    | Không thực hiện kiểm tra bằng rule ModSecurity   | Cần đối chiếu báo cáo               | Quan sát hành vi ứng dụng khi tắt WAF           |
| DetectionOnly          | `SecRuleEngine DetectionOnly`          | Custom Rule ID `10001` ghi cảnh báo              | `200` trong các mẫu log đã cung cấp | Phát hiện nhưng không chủ động chặn             |
| Blocking - Custom Rule | `SecRuleEngine On`                     | Ghi nhận `Access denied`                         | `403`                               | Custom Rule từ chối request                     |
| Blocking - OWASP CRS   | `SecRuleEngine On` và CRS được áp dụng | Ghi nhận sự kiện RCE và đánh giá điểm bất thường | `403` theo báo cáo                  | CRS thực hiện phát hiện kết hợp với cơ chế chặn |

Các mã HTTP trong bảng phản ánh những lần kiểm thử được báo cáo, không phải kết quả bảo đảm cho mọi request hoặc mọi cấu hình. Khi đánh giá hiệu quả bảo vệ, cần đối chiếu đồng thời request, response và log tương ứng.

## 9. Kết quả và nhận xét

Qua các giai đoạn kiểm thử, dự án minh họa ba khía cạnh chính của bảo vệ ứng dụng web:

* **Phát hiện:** Custom Rule có thể nhận diện một số dấu hiệu đáng ngờ trong tham số đầu vào và ghi lại sự kiện trong log.
* **Ngăn chặn:** Khi chế độ chặn được bật, request khớp rule có thể bị từ chối với HTTP 403.
* **Phát hiện theo bộ quy tắc:** OWASP CRS cung cấp nhiều rule chuyên biệt và cơ chế đánh giá điểm bất thường nhằm hỗ trợ phát hiện các nhóm tấn công web.

Dự án cũng cho thấy việc phân tích log là một phần quan trọng trong quy trình giám sát an ninh. Người phân tích cần liên kết nội dung request, rule ID, thông báo cảnh báo và HTTP response để xác định sự kiện thực sự diễn ra.

## 10. Hạn chế

* Custom Rule dựa trên biểu thức chính quy có thể tạo false positive đối với dữ liệu hợp lệ chứa các ký tự được giám sát.
* Rule đơn giản không thể nhận diện mọi biến thể Command Injection, đặc biệt khi dữ liệu được mã hóa hoặc biến đổi.
* Kết quả kiểm thử trên DVWA không đại diện cho hiệu quả bảo vệ đối với mọi ứng dụng web thực tế.
* HTTP 403 và cảnh báo trong log cần được đối chiếu với luồng xử lý thực tế trước khi kết luận về việc ngăn chặn thực thi lệnh.
* Chưa thể đánh giá đầy đủ false positive, false negative và hiệu năng nếu chưa có bộ kiểm thử mở rộng.

## 11. Hướng phát triển

* Mở rộng bộ ca kiểm thử với cả request hợp lệ và request độc hại để đánh giá false positive.
* Tinh chỉnh Custom Rule theo yêu cầu của ứng dụng, tránh chặn nhầm dữ liệu hợp lệ.
* Nghiên cứu thêm cấu hình OWASP CRS và các mức Paranoia Level phù hợp.
* Chuẩn hóa việc thu thập, lọc và phân tích log để phục vụ điều tra sự cố.
* Nghiên cứu tích hợp log với hệ thống quản lý sự kiện bảo mật như ELK Stack hoặc Splunk.
* Bổ sung tài liệu tái hiện lab, ảnh bằng chứng và kết quả kiểm thử có thể kiểm chứng.

## 12. Tài liệu tham khảo

* [OWASP Core Rule Set](https://coreruleset.org/)
* [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)
* [ModSecurity-nginx Connector](https://github.com/owasp-modsecurity/ModSecurity-nginx)
* [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA)

## 13. Tuyên bố sử dụng

Dự án được xây dựng nhằm mục đích học tập, nghiên cứu và thực hành phòng thủ an toàn thông tin trong môi trường lab được kiểm soát. Không sử dụng các kỹ thuật kiểm thử này trên hệ thống khi chưa được chủ sở hữu cho phép.
