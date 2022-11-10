#pragma once

/**
 * @brief Check if a char* is a positive integer, returns the converted number or exits the program
 *
 */
int check_number(const char *number);

/**
 * @brief Checks if a string is a valid port number
 *
 * @param port
 */

void check_port(string port);

/**
 * @brief Finds the latest flow in the map structure
 *

 */
tuple<in_addr_t, in_addr_t, int, int, int, int> find_latest(map<tuple_key, flow> flows);

/**
 * @brief Helper function for sorting flows
 *
 */
bool compareFlows(flow f1, flow f2);
