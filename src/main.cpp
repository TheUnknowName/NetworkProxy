#include "app/application.h"

int main(int argc, char* argv[]) {
    network_proxy::Application application;
    return application.run(argc, argv);
}
