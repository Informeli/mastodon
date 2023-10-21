#  <one line to give the program's name and a brief idea of what it does.>
#    Copyright (C) 2023  Martin Smouter
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 #   GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#    You can contact Martin Smouter through epv76lk5k@mozmail.com

class CommunityNoteValidator < ActiveModel::EachValidator
  #intern length of the hashvalues needed for injection protection
  hash_length = 32
  def validate(note)
  # Obtain key based on the noter. This currently has to be added manually by
  # the server admin. Just like the certificates currently have to be generated
  # manually.
  key
  if File.exist("./"+note.noter+".key")
    file = File.open("./"+note.noter+".key")
    key = file.read()
    file.close
    end
  values = option_to_value(note.cert, key).split('')
  
  
  # Here I distinguish various parts of the certificate based on their 
  # indexes in the certificate. This is to avoid injection attacks.
  # I do this pretty manual, because I wanted to make sure I took up as
  # little bandwidth as possible and it forces me to consider the needs of each
  # variable individually. If you want to automate it in later date
  
  #each unix timestamp can fit in a byte and thus in a single variable
  if values[0] != note.date_time
    return false
    end
  # hashes have a previously defined size. The fact that md5 was one day 
  # cryptographically secure doesn't matter. If you know a more preformant
  # hashing algorithm in ruby implement it instead of
  
  if values[1...hashsize+1].join() != MD5.hexvalue=note.note_content
    return false
    end
  if values[hashsize+1...-1].join() != note.post_identifier
    return false
    end
  # the rest won't succeed either when the noter doesn't match, because the key 
  # is bound to them.
  return true
  end
end
