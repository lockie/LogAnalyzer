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


#include <cstdio>

#include "analyzer.h"

int main() {
  LogAnalyzer* analyzer = new LogAnalyzer("../var/logs/access.log");  
  
  analyzer->do_analyze();
  analyzer->clear_file();
  
  delete analyzer;  
  
  return 0;  
}
