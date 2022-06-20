def main():
    hashtagremoval()
    filtering_ip()

#removing hashtags from conn.log, because this caused problems with indexing in array
def hashtagremoval():
    filepath = "/opt/zeek/logs/2022-06-06/conn.log"
    a_file = open(filepath, "r")
    lines = a_file.readlines()
    a_file.close()

    for x in range(0, 8):
        del lines[0]

    new_file = open(filepath, "w+")
    for line in lines:
        new_file.write(line)
        new_file.close()

#filtering/selecting all ip addresses from log file.
def filtering_ip():
    filepath = "/opt/zeek/logs/2022-06-06/conn.log"
    ip_filterd = {"127.0.0.1"}
    w = open("zeek.log", "w+")
    f = open(filepath, "r")
    for line in f:
        linestrip = line.strip().split("\t")
        try:
            ip = linestrip[2]
            ip_filterd.add(ip)
        except (IndexError) as error:
            pass

    w.write(f"{ip_filterd}")
    f.close()
    w.close()


if __name__ == "__main__":
    main()