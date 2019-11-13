#include "handler.h"

const int BUFSIZE = 16384;
const char IMG[] = "image/a.jpg\0";
const char UPLOAD_FOLDER[] = "upload/\0";
const char JS_CODE[] = "<script type='text/javascript'>"
                        "alert('ok')"
                        "</script>";
const int END_FLAG_LEN = 46;



void handle_socket(int fd)
{
    long i, j, ret;
    static char buffer[16385];

    ret = read(fd, buffer, BUFSIZE); /* 讀取瀏覽器要求 */
    if (ret == 0 || ret == -1) {
        // connection failed
        exit(3);
    }
    if (ret < BUFSIZE)
        buffer[ret] = 0;
    else
        buffer[0] = 0;

    // read request type
    char req[20];

    for (i = 0; i < ret; i++) {
        req[i] = buffer[i];
        if (buffer[i] == '\r' || buffer[i] == '\n')
            break;
    }
    req[i] = 0;

    // analyze request
    if (!strncmp(req, "GET ", 4) || !strncmp(req, "get ", 4)) {
        printf("GET\t");
        if (strstr(req, " / ")) { // index.html
            get_index(fd);
            printf("/");
        } else if (strstr(req, ".jpg")) { // show image
            get_img(fd);
            printf("/%s", IMG);
        }
    }
    if (!strncmp(req, "POST ", 5) || !strncmp(req, "post ", 5)) {
        printf("POST\t");
        if (strstr(req, "/upload")) { // upload file
            printf("/upload");
            post_upload(fd, buffer);
        }
    }
    puts("");
    exit(1);
}

char* __get_file_name_and_skip_header(const char* src, char* dest)
{
    // src: original content in buf
    // dest: uploaded file name with folder.
    // return file's content (char*) with endding mark.
    int i = 0;
    char* start; // file infomation start

    start = strstr(src, "filename=\"");
    start += 10;
    char* end = strstr(start, "\"");

    // save filename
    for (i = 0; UPLOAD_FOLDER[i] != 0; ++i)
        dest[i] = UPLOAD_FOLDER[i];
    for (char* p = start; p != end; ++p, ++i)
        dest[i] = *p;
    dest[i] = 0;

    // skip header info with three \n
    start = strstr(start, "\n");
    start = strstr(start + 1, "\n");
    start = strstr(start + 1, "\n");
    ++start;
    return start;
}

void post_upload(int fd, char* buf)
{
    char file[256], *start_pos;
    int out_fd, ret_read, write_size;

    // read request until have file name
    while (!strstr(buf, "filename=")) {
        ret_read = read(fd, buf, BUFSIZE);
    }
    // get file name and content starting position.
    start_pos = __get_file_name_and_skip_header(buf, file);

    out_fd = open(file, O_CREAT | O_TRUNC | O_WRONLY | O_SYNC, S_IRWXO | S_IRWXU | S_IRWXG);
    // write content into file
    // if ret_read != BUFSIZE:
    //     file's content is all in buf. split endding flag(46 chars).
    // else: need next content(no enddinh flag)
    write_size = ret_read - (ret_read < BUFSIZE ? END_FLAG_LEN : 0) - (start_pos - buf);
    write(out_fd, start_pos, write_size);

    while (ret_read == BUFSIZE) {
        ret_read = read(fd, buf, BUFSIZE);
        write_size = ret_read - (ret_read != BUFSIZE ? END_FLAG_LEN : 0);
        write(out_fd, buf, write_size);
    }
    close(out_fd);

    // show home page and OK.
    get_index(fd);
    write(fd, JS_CODE, strlen(JS_CODE));
}

void get_index(int fd)
{
    const char html_header[] = "HTTP/1.1 200 Ok\r\n"
                            "Content-Type: text/html\r\n\r\n";

    char buffer[BUFSIZE + 1];
    int html_fd = open("index.html", O_RDONLY);

    write(fd, html_header, sizeof(html_header) - 1);

    while (read(html_fd, buffer, BUFSIZE) != 0) {
        write(fd, buffer, strlen(buffer));
        memset(buffer, 0, sizeof buffer);
    }
    close(html_fd);
}

void get_img(int fd)
{
    const char img_header[] = "HTTP/1.1 200 Ok\r\n"
                              "Content-Type: image/jpeg\r\n\r\n";
    char buf[BUFSIZE + 1];
    int img_fd = open(IMG, O_RDONLY);

    write(fd, img_header, sizeof(img_header) - 1);
    while (read(img_fd, buf, sizeof buf) != 0) {
        write(fd, buf, sizeof(buf));
        memset(buf, 0, sizeof buf);
    }
    close(img_fd);
}