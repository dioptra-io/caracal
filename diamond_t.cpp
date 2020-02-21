//
// Created by System Administrator on 2019-02-11.
//

#include "diamond_t.hpp"

bool operator==(const diamond_t &d1, const diamond_t d2) {
    return d1.m_divergence_point == d2.m_divergence_point && d1.m_convergence_point == d2.m_convergence_point;
}
