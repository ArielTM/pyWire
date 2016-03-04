import os


class LayerField(object):
    """
    Holds all data about a field, its value and nice representation.
    """
    def __init__(self, fieldXml , parentName):
        # must have attributes
        self._attr_name = None
        self._attr_showname = None
        self._attr_value = None
        self._attr_show = None
        self._attr_pos = None
        self._attr_size = None
        self._attr_unmaskedvalue = None
        self._attr_hide = None
    
        # extract attributes of field
        self._attributesNames = fieldXml.attrib.keys()
        for attrName ,attrVal in fieldXml.attrib.items():
            self.__setattr__( '_attr_' + attrName, attrVal)
        
        # decide on a name for this field.
        if self._attr_name is not None:
            parentName = parentName.replace('_' , '.') 
            if self._attr_name.find(parentName) != -1:
                self._attr_name = self._attr_name.split(parentName)[1]
        self._name = MakeName(self._attr_name)
        if self._name is None or self._name == '':
            if self._attr_show is not None:
                self._name = MakeName(self._attr_show.split(':')[0])
            if self._name is None or self._name == '':
                self._name = MakeName(self._attr_showname)
                if self._name is None or self._name == '':
                    self._name = 'pos_' + str(self._attr_pos) + '_size_' + str(self._attr_size)

        # decide whether this field is hidden when printing
        self._hide = (self._attr_hide == 'yes')
        if self._hide:
            self._name = '_hid_' + self._name
        
        # if field name doesn't start with a letter or underscore, add 'field_'
        firstChar = self._name[0]
        if not (firstChar.isalpha() or firstChar == '_'):
            self._name = 'field_' + self._name
        
        # extract sub fields. notice some may have the same name or no name
        self._subFieldsNames = AddSubFields(self , fieldXml)

    def TryGetAttribute(self , attrName):
        ''' for internal usage '''
        if attrName in self._attributesNames:
            return self.__getattribute__(attrName)
        else:
            return None
      
    @property
    def val_(self):
        """
        Return the value of the field
        """
        val = self._attr_show
        if val is None:
            val = self._attr_value
        if not val:
            val = field.showname
        return val
        
    def __str__(self):
        ''' return string representation of the layer '''
        if self._hide:
            return ''
        s = ''
        if self._attr_showname is not None:
            s += self._attr_showname
        elif self._attr_show is not None:
            s += self._attr_show
        else:
            s += self._name + ':\t'
            s += self._attr_value
        s += os.linesep
        
        s += StrSubFields(self , self._subFieldsNames)
        
        return s
        
    def __iter__(self):
        ''' 
            Return self.
            This is just for convenience when trying to iterate on a sub field which
            it is not known whether it is a list or not.
        '''
        yield self
        
    def IterateSubfieldsNames(self , dontShowHidden = True):
        '''
            Iterate over the sub fields names.
            Note that some fields may share the same name.
            In that case, the name will be returned only once.
        '''
        for subfieldName , subfieldOccur in self._subFieldsNames:
            if subfieldOccur == 0:  # iterate each field name just once
                if not (dontShowHidden and subfieldName.startswith('_hid_')):
                    yield subfieldName
            
    def IterateSubfields(self , dontShowHidden = True):
        '''
            Iterate over the sub fields of this field.
            Each sub field will be return, even if it share its name with others.
        '''
        for subfieldName in self.IterateSubfieldsNames(dontShowHidden):
            for subField in self.__getattribute__(subfieldName):    # in case of list
                yield subField
        
    def IterateSubFieldsTree(self , dontShowHidden = True):
        '''
            iterate over the sub fields tree in DFS.
            Each sub field will be return, even if it share its name with others.
        '''
        for subField in self.IterateSubfields(dontShowHidden):
            yield subField
            for subSubField in subField.IterateSubFieldsTree(dontShowHidden):
                yield subSubField
                
    def StrSubFieldsTree(self , dontShowHidden = True ):
        '''
            return string representation of the sub fields tree.
        '''
        s = ''
        for subField in self.IterateSubfields(dontShowHidden): 
            s += subField._name + '\n'
            s += TabString(subField.StrSubFieldsTree(dontShowHidden))
        return s
        
    def PrintSubFieldsTree(self,dontShowHidden = True  ):
        '''
            print string representation of the sub fields tree.
        '''
        print self.StrSubFieldsTree(dontShowHidden)
        
    def SearchSubField(self, subString ,recursive = False, dontShowHidden = True):
        '''
        Return list of sub fields that contains the subString in their name
        '''
        res = []
        
        if recursive:
            iterOnFields = self.IterateSubFieldsTree(dontShowHidden)
        else:
            iterOnFields = self.IterateSubfields(dontShowHidden)

        for subField in iterOnFields:
            if subString in subField._name:
                res.append(subField)
        return res
        
    def __repr__(self):
        s = ''
        s += '<Field %s' % (self._name)
        if len(self.val_) < 20:
            s += ', Value: %s' % ( self.val_)
        s += ', #subfields %d' % len(self._subFieldsNames)
        s += '>'
        return s
        
def MakeName(someStr):
    '''
    return a string which might be a name for a field
    '''
    if someStr is None:
        return None
    isGotAnyAlnum = False
    isLastCalnum = False
    newStr = ''
    for c in someStr:
        if c.isalnum():
            isGotAnyAlnum = True
            isLastCalnum = True
        else:
            # replace not good chars with single underscore
            if isLastCalnum:
                c = '_'
            else:
                c = ''
            isLastCalnum = False

        newStr += c
    if isGotAnyAlnum:
        return newStr
    else:
        return None

def AddSubFields(obj , xmlObjWithFields):
    '''
    iterate over xml object with fields, and add each one of them to the object.
    return list of fields names that were added
    '''
    subFieldsNames = []
    if xmlObjWithFields.countchildren() >0:
        if getattr(xmlObjWithFields , 'field' , False) != False:
            # there are some sub fields
            for subFieldXml in xmlObjWithFields.field:
                theField = LayerField(subFieldXml , obj._name)
                subFieldName = theField._name
                occurIndex = AddSubField(obj, subFieldName , theField)
                subFieldsNames.append((subFieldName , occurIndex))
        #else:
            # sometimes there is another proto field inside another field
            # for example NTLM proto inside http.authorization
            # its probably a bug in wireshark...
            # print xmlObjWithFields.attrib
            # print xmlObjWithFields.proto[0].attrib
    return subFieldsNames

def AddSubField(obj , subFieldName , subFieldVal):
    '''
    add sub field to an object, where theField._name will be its name.
    if duplicates exist - create list instead
    return the number of occurrences of the fields with the same name
    '''
    oldAttrVal = getattr(obj , subFieldName , 'ErrorNotExist')
    if  oldAttrVal == 'ErrorNotExist':
        # subField does not exist
        obj.__setattr__( subFieldName, subFieldVal)
        return 0
    else:
        # subField with this name already exist
        if type(oldAttrVal) != list:
            # already more then one sub field
            oldAttrVal = [oldAttrVal , ]
            obj.__setattr__( subFieldName, oldAttrVal)
            
        # add the new field
        obj.__getattribute__(subFieldName).append(subFieldVal)
        return len(obj.__getattribute__(subFieldName)) - 1
        
def StrSubFields(obj , subFieldsNames):
    s = ''
    for subFieldName , occurIndex in subFieldsNames:
       s +=  TabString(StrSubField(obj.__getattribute__(subFieldName) , occurIndex))
    return s
    
def StrSubField(subField , occurIndex):
    s = ''
    if type(subField) == list:
        s += str(subField[occurIndex])
        return s
    else:
        return str(subField)
    
def TabString(theStr):
    theStr = '\t' + theStr.replace('\n' , '\n\t')
    return theStr[:-1]
        
class Layer(object):
    """
    An object representing a Packet layer.
    Sub fields can be accessed by their names: layer.subFieldName 
    """
    _DATA_LAYER = 'data'

    def __init__(self, xml_proto_obj=None, raw_mode=False):
        self._raw_mode = raw_mode
        
        # extract attributes of protocol
        self._attributesNames = xml_proto_obj.attrib.keys()
        for attrName ,attrVal in xml_proto_obj.attrib.items():
            self.__setattr__( '_attr_' + attrName, attrVal)
        self._name = self.layer_name
        # extract subfields. notice some may have the same name or no name
        self._subFieldsNames = AddSubFields(self , xml_proto_obj)

    def TryGetAttribute(self , attrName):
        ''' for internal usage '''
        if self.__dict__.has_key(attrName):
            return self.__getattribute__(attrName)
        else:
            return None
    
    def IterateSubfieldsNames(self , dontShowHidden = True):
        '''
            Iterate over the subfields names.
            Note that some fields may share the same name.
            In that case, the name will be returned only once.
        '''
        for subfieldName , subfieldOccur in self._subFieldsNames:
            if subfieldOccur == 0:  # iterate each field name just once
                if not (dontShowHidden and subfieldName.startswith('_hid_')):
                    yield subfieldName
            
    def IterateSubfields(self , dontShowHidden = True):
        '''
            Iterate over the subfields of this field.
            Each subfield will be return, even if it share its name with others.
        '''
        for subfieldName in self.IterateSubfieldsNames(dontShowHidden):
            for subField in self.__getattribute__(subfieldName):    # in case of list
                yield subField
    
    def IterateSubFieldsTree(self , dontShowHidden = True):
        '''
            iterate over the sub fields tree in DFS.
            Each sub field will be return, even if it share its name with others.
        '''
        for subField in self.IterateSubfields(dontShowHidden):
            yield subField
            for subSubField in subField.IterateSubFieldsTree(dontShowHidden):
                yield subSubField
                
    def StrSubFieldsTree(self , dontShowHidden = True ):
        '''
            return string representation of the sub fields tree.
        '''
        s = ''
        for subField in self.IterateSubfields(dontShowHidden): 
            s += subField._name + '\n'
            s += TabString(subField.StrSubFieldsTree(dontShowHidden))
        return s
        
    def PrintSubFieldsTree(self,dontShowHidden = True  ):
        '''
            print string representation of the sub fields tree.
        '''
        print self.StrSubFieldsTree(dontShowHidden)
            
    def SearchSubField(self, subString ,recursive = False, dontShowHidden = True):
        '''
        Return list of sub fields that contains the subString in their name
        '''
        res = []
        
        if recursive:
            iterOnFields = self.IterateSubFieldsTree(dontShowHidden)
        else:
            iterOnFields = self.IterateSubfields(dontShowHidden)

        for subField in iterOnFields:
            if subString in subField._name:
                res.append(subField)
        return res
            
            
    @property
    def layer_name(self):
        '''
            return the name of this layer
        '''
        if self._attr_name == 'fake-field-wrapper':
            return self._DATA_LAYER
        return self._attr_name
    
    def __repr__(self):
        s = ''
        s += '<%s Layer' % self.layer_name.upper()
        s += ', #subfields %d' % len(self._subFieldsNames)
        s += '>'
        return s
    
    def __str__(self):
        if self.layer_name == self._DATA_LAYER:
            return 'DATA'

        s = 'Layer %s:' % self.layer_name.upper() + os.linesep
        s += StrSubFields(self , self._subFieldsNames)
        return s
   
           