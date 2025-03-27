#include "host.h"
#include <vector>
int main(int argc, char *argv[]) {
    const char *servername = NULL;
    if (argc == 2) {
        servername = argv[1];
    }
    std::vector<Host*> hosts;
    for (int i = 0; i < 1; i++) {
        Host *host = new Host(3, 19875 + i, servername, "mlx5_0", servername == NULL);
        hosts.push_back(host);
        host->run_in_thread();
    }
    while(1);

    return 0;
}