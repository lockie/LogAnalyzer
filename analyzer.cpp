/*
    This program is free software; you can redistribute it and/or modify
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


#if _MSC_VER >= 1400
#pragma warning(disable:4996)
#endif

#include <stdarg.h>
#include <time.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>

#include "mysql.h"

#include "analyzer.h"

using namespace std;

// 4Kbytes seems to be big enough =)
#define BUFFER_SIZE 4096
static char buffer[BUFFER_SIZE]; 
static char tmp_buf[BUFFER_SIZE] ;
static char buff[BUFFER_SIZE];

static MYSQL mysql;

/* can use NULL for localhost, current user, or no password */
#define DBHOST "localhost"
#define DBUSER "usergate"
#define DB "squid"
#define DBPASSWORD "my-secret-pw"

#define PERCENT 0.1
#define MEGABYTE 1048576.0


LogAnalyzer::LogAnalyzer(const char* log_filename) {
  filename = log_filename;  
  log.open("analyzer.log", ios_base::out | ios_base::app); 
  // put time 2 log
  time_t* curr_time = new time_t;
  time(curr_time);
  tm* Tm = localtime (curr_time);
  delete curr_time;
  log << "---------------------------------------------------" << endl;  
  strftime(tmp_buf, BUFFER_SIZE, "Analyzer started %Y-%m-%d %H:%M:%S ", Tm);  
  log << tmp_buf << endl;  
  log << "---------------------------------------------------" << endl;
}

LogAnalyzer::~LogAnalyzer() {
  log.close();  
}


static tm Time;

const char*   LogAnalyzer::get_date(istringstream& line) {
  line >> tmp_buf;
  unsigned long time = atol(tmp_buf);
#ifdef _MSC_VER
  _localtime32_s(&Time, (__time32_t*)&time); // motherfucking studio
#else
  localtime_r((time_t*)&time, &Time);
#endif
  strftime(tmp_buf, BUFFER_SIZE, "%Y-%m-%d", &Time);
  return tmp_buf;  
}

const char*   LogAnalyzer::get_time(istringstream& line) {
  strftime(tmp_buf, BUFFER_SIZE, "%H:%M:%S", &Time);
  return tmp_buf;
}

const char*   LogAnalyzer::get_ip(istringstream& line) {
  line >> tmp_buf;
  line >> tmp_buf; // so here finally comes ip
  return tmp_buf;
}

const char*   LogAnalyzer::get_result(istringstream& line) {
  line >> tmp_buf;
  return tmp_buf;
}

unsigned long LogAnalyzer::get_bytes(istringstream& line) {
  line >> tmp_buf;
  return atol(tmp_buf);  
}

const char*   LogAnalyzer::get_url(istringstream& line) {
  line >> tmp_buf;
  line >> tmp_buf;
  return tmp_buf;
}

const char*   LogAnalyzer::get_username(istringstream& line) {
  line >> tmp_buf;
  return tmp_buf;
}

#define NUM_ROWS 3
static char* row_array[NUM_ROWS];

char** __cdecl LogAnalyzer::MySQL_query(char* query, ...) {
  // deal with varargs
  va_list args;
  va_start(args, query);
  vsnprintf(buff, BUFFER_SIZE, query, args);
  va_end(args);
  MYSQL_RES* res;
  if(mysql_query(sock,buff)) {
    log << "-=WARNING=-: The following query failed: \"" << buff << "\"" << endl;
    log << "With message : " << mysql_error(&mysql);      
    return NULL;
   } else {
    res = mysql_store_result(sock);
    if(mysql_num_rows(res)!=0) {
      char** row = mysql_fetch_row(res);    
      // copy result
      unsigned int fields = mysql_num_fields(res);
      for(unsigned int i = 0; i<fields; i++) {
        delete row_array[i];
        row_array[i] = new char[strlen(row[i]) + 1];
        strcpy(row_array[i], row[i]);
      }
      mysql_free_result(res);
      return row_array;
     } else {
      log << "-=WARNING=-: Result of query: \"" << buff << "\" ";
      log << "have 0 rows" << endl;
      mysql_free_result(res);      
      return NULL;
    }
  }  
}


double LogAnalyzer::get_session_cost(std::string username, unsigned long* id, char** balance) {
  char** row = MySQL_query("SELECT id, tarif, balance FROM proxy_users WHERE username='%s'", username.c_str());     
  if(!row) return 0; // wrong user
  *id = atol(row[0]);
  strcpy(*balance, row[2]);
  // now row[1] is tariff id
  
  char** row2 = MySQL_query("SELECT sent,recv FROM tarifs WHERE id='%s'", row[1]);
  if(!row2) {
    log << "Oops, its very bad :O" << endl;
    abort();    
  }
  // calculate cost
  return atof(row[1]) + atof(row[0])*PERCENT ;
}


MYSQL* LogAnalyzer::init_MySQL() {
  MYSQL* sock;
  mysql_init(&mysql);
  if (!( sock = mysql_real_connect(&mysql,DBHOST,DBUSER,DBPASSWORD,DB,0,NULL,0) )) 
  {
    log << "-=ERROR=-: Could not connect to MySQL with host=" << DBHOST << " user=" << DBUSER << endl;
    log << "With message : " << mysql_error(&mysql);      
    abort();
  }
  if (mysql_select_db(sock, DB))
  {
    log << "-=ERROR=-: Could not select database \"" << DB << "\"=" << endl;
    log << "With message : " << mysql_error(&mysql);
    mysql_close(sock);     
    abort();
  }
  return sock;
} 

void LogAnalyzer::do_analyze() {
  // open logfile
  ifstream file(filename);
  if(!file) {
    log << "-=ERRROR=-: Unable to open file \"" << filename << "\"" << endl;
    abort();
  }

  // generate file name - hey kids what time is it? =)
  time_t* curr_time = new time_t;
  time(curr_time);
  tm* Tm = localtime (curr_time);
  delete curr_time;
  strftime(buff, BUFFER_SIZE, "_%Y%m%d_%H%M%S.log", Tm);
  strcpy(tmp_buf, filename);
  strcat(tmp_buf, buff);
  ofstream new_file(tmp_buf);
  if(!new_file) {
    log << "-=ERROR=-: Unable to open for writing: \"" << tmp_buf << "\"" << endl;
    abort();
  }

  // parse file  
  istringstream line;
  string date;
  string time;
  string ip;
  string result;
  unsigned long bytes;
  string url;
  string username;
  unsigned long user_id;
  double cost;
  char* c_balance = new char[64];
  double balance;

  sock = init_MySQL();

  while(file.good()) {
    // do buffer    
    file.getline(buffer, BUFFER_SIZE-1);    
    line.str(buffer);  
    // copy old file to new
    new_file <<  buffer << endl;

    date = get_date(line);
    time = get_time(line);
    ip = get_ip(line);
    result = get_result(line);
    bytes = get_bytes(line);
    url = get_url(line);
    username = get_username(line);

    // test 4 bad strings
    if(ip.length()==0 || result.length()==0 || url.length()==0) {
      log << "-=WARNING=-: Bad string in file:" << endl;
      log << buffer << endl;
      continue;
    }

    cost = bytes * get_session_cost(username, &user_id, &c_balance) / MEGABYTE;
    
    if(cost) {
      balance = atof(c_balance);
      balance-=cost;
      sprintf(tmp_buf, "UPDATE proxy_users SET balance='%f' WHERE id='%d'", balance, user_id);
      mysql_query(sock,tmp_buf);
    }

    sprintf(tmp_buf, "INSERT INTO traffic values('','%s','%s','%s','%s','%u','%f','%s','%s','%d')", 
      date.c_str(), time.c_str(), ip.c_str(), result.c_str(), bytes, cost, url.c_str(), username.c_str(), user_id);
    if(mysql_query(sock, tmp_buf))
    {
      log << "-=ERROR=-: The following query failed: \"" << tmp_buf << "\"" << endl;
      log << "With message : " << mysql_error(sock);
      mysql_close(sock);     
      abort();    
    }   
  }

  //mysql_free_result(res);
  mysql_close(sock);
  sock = NULL;
  delete c_balance;
  
  // close logfile
  new_file.close();
  file.close();   
}

void LogAnalyzer::clear_file() {
  // copy file to backup & emty its contens
  
  // just open file for writing to delete its content
  ofstream f(filename);
  if(f) f.close();
    else {
    log << "-=ERROR=-: Unable to clear contens of old file \"" << filename << "\"" << endl;
    abort();
  }
    
}
