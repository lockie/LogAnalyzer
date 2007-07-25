/*
    log program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    log program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with log program.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef _ANALYZER_H_
#define _ANALYZER_H_

#include <sstream>
#include <fstream>

#include "mysql.h"

#ifdef __GNUC__
#define __cdecl __attribute__((cdecl))
#endif

class LogAnalyzer {
private:
  LogAnalyzer();
  LogAnalyzer(const LogAnalyzer&);

  const char* filename; 
  
  std::ofstream log;
  
  MYSQL* sock;

  MYSQL* init_MySQL();

  char** __cdecl MySQL_query(char*, ...);

  const char*   get_date(std::istringstream&);
  const char*   get_time(std::istringstream&);
  const char*   get_ip(std::istringstream&);
  const char*   get_result(std::istringstream&);
  unsigned long get_bytes(std::istringstream&);
  const char*   get_url(std::istringstream&);
  const char*   get_username(std::istringstream&);

  double get_session_cost(std::string, unsigned long*, char**);


public:
  LogAnalyzer(const char*);
  ~LogAnalyzer();

  void do_analyze();
  void clear_file();
}  ;

#endif   //  _ANALYZER_H_
