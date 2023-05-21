#include "random.h"

std::random_device rand_dev;
std::mt19937 generator(rand_dev());
