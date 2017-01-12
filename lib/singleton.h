/*
 *
 */
class SingletonProcess {
public:
	SingletonProcess(uint16_t port0) :
			socket_fd(-1), rc(1), port(port0) {
		socket_fd = -1;
	}

	~SingletonProcess() {
		if (socket_fd != -1) {
			close(socket_fd);
		}
	}

	bool operator()() {
		if (socket_fd == -1 || rc) {
			socket_fd = -1;
			rc = 1;

			if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
				throw std::runtime_error(
						std::string("Could not create socket: ")
								+ strerror(errno));
			} else {
				struct sockaddr_in name;
				name.sin_family = AF_INET;
				name.sin_port = htons(port);
				name.sin_addr.s_addr = htonl(INADDR_ANY);
				rc = bind(socket_fd, (struct sockaddr *) &name, sizeof(name));
			}
		}
		return (socket_fd != -1 && rc == 0);
	}

	std::string GetLockFileName() {
		std::ostringstream stm ;
		stm << "port " << port;
		return stm.str();
		//return "port " + std::to_string(port);
	}

private:
	int socket_fd;
	int rc;
	uint16_t port;
};

