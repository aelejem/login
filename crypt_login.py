import csv

class Crypt:
    def _moveChar(self, inpstr:str, intval:int=0):
        char = "abcdefghijklmnopqrstuvwxyz"
        if not inpstr.isalpha():
            return inpstr
        for value in inpstr:
            upper = 0
            if value.isupper():
                upper = 1
                value = value.lower()
            val = char.index(value)
            val += int(intval)
            val %= 26
            if upper:
                return char[val].upper()
            else:
                return char[val]
            
    def crypt(self, inpval:str, ed:bool, cVal=0):
        # make cVal into a tuple
        cVal = (cVal,) if type(cVal) == int else tuple(cVal)
        # determines if this would en- or de- cypher
        if not ed:
            cVal = [(26-x)%26 for x in cVal]
        else:
            cVal = [x%26 for x in cVal]
        
        iter = 0
        output = []
        for inst in inpval:
            output.append(self._moveChar(inst, cVal[iter]))
            if iter == len(cVal)-1:
                iter = 0
            else:
                iter += 1
        return ''.join(output)


    def codeFiles(self, filename:str, ed:bool, arg=0, final_file_name:str=False):
        try:
            with open(filename, 'r') as file:
                readfile = file.read().strip('\n').split('\n')
        except:
            print("no file")
            return False
        res = []
        for inst in readfile:
            res.append(self.code(inst, ed, arg))
        if final_file_name:
            with open(final_file_name, 'w') as file:
                for inst in res:
                    file.write(inst+'\n')
        return [x+'\n' for x in res]
    
class Log(Crypt):
    def __init__(self, filename:str, enc=0):
        try:
            with open(filename, 'r') as file:
                reader = csv.reader(file)
                lgpw = [x for x in reader]

            lgData = eval(self.crypt(str(lgpw), False, enc))
            self.decData = []
            headers = lgData.pop(0)
        
            # Iterate over each row in the CSV file
            for row in lgData:
                row_dict = dict(zip(headers, row))
                # Append the dictionary to the list
                self.decData.append(row_dict)
        except:
            self.decData = []
            
        finally:
            self.enc = enc
            self.filename = filename

    def savestate(self, filename:str="init", enc=0):
        if enc == 0:
            enc = self.enc

        if filename == "init":
            filename = self.filename
        if not self.decData:
            with open(filename, 'w'):
                pass
            return True
        headers = list(self.decData[0].keys())
        res = []
        res.append(headers)
        for inst in self.decData:
            row_values = [inst[header] for header in headers]
            res.append(row_values)

        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(eval(self.crypt(str(res), True, enc)))

        return True

        
    def login(self, id:str, pw:str):
        for row in self.decData:
            if row["ID"] == id and row["Password"] == pw:
                return row
        return False
    

    def signin(self, name:str, id:str, pw:str):
        for row in self.decData:
            if row["ID"] == id:
                return False
        if self.decData:
            self.decData.append({"Name": name, "ID": id, "Password":pw})
            print(self.decData)
        else:
            self.decData = [{"Name": name, "ID": id, "Password":pw}]
