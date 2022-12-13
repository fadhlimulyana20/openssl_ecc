#include <iostream>
#include "crow.h"

using namespace std;

int main()
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")
    ([]()
     { return "Hello world"; });

    app.port(18080).multithreaded().run();
}
