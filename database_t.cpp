//
// Created by System Administrator on 2019-02-06.
//

#include <iostream>
#include "database_t.hpp"

using namespace pqxx;
database_t::database_t() :
// SSH tunneling
m_connection{"dbname = internet_snapshot user = kevin password = kevin "
"hostaddr = 127.0.0.1 port = 5432"}
{
    if (m_connection.is_open()) {
        std::cout << "Opened database successfully: " << m_connection.dbname() << "\n";
    } else {
        std::cout << "Can't open database\n";
    }
}


pqxx::connection & database_t::get_connection() {
    return m_connection;
}
