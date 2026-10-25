#include "policy.h"
#include <iostream>

int main() {
  try {
    std::cout << "{\"protocolVersion\":1,\"selfTest\":\"passed\",\"cases\":"
              << network_guard::selfTest() << "}\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
