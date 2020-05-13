#!/usr/bin/env python3
# v1.1
"""
This is a tool for WSDL testing processes. The program helps you to fuzz requests using a WSDL file. It aims to create all possible requests and forward them to a custom proxy, e.g. Burp.

Call this script with wsdl files as parameter.

Set variable SOAP!

Es werden alle möglichen Anfragen generiert und an Burp weitergeleitet. Bei sich ausschließenden Parametern („Choice") werden pro Methode mehrere Anfragen generiert, sodass jeder Parameter mindestens einmal vorkommt. Für jede Methode wird zusätzlich eine Anfrage ohne optionale Parameter generiert.
"""

import os, sys, datetime, zeep, itertools
from zeep import Client, Settings
from zeep.xsd.elements.indicators import Choice, Element

SOAP = "http://your-soapserver.ex"
PROXY="127.0.0.1:8080" # burp
#PROXY=None
INCLUDE_OPTIONAL_ARGUMENTS = True
DEFAULT_VALUE="0"
DEFAULT_VALUES = dict(
    KeyName="Default_Value",
)


OKC = '\033[92m'
FAIL = '\033[91m'
WARNING = '\033[93m'
ENDC = '\033[0m'


if len(sys.argv) <= 1:
    print("Arguments missing: Give a list of wsdl files as input, e.g. /PATH/*.wsdl.")
    print("Note: You can define a burp proxy, desired XML values and the soap URL in the source code.")
    exit(1)


class WsdlTreeParser(object):

    @classmethod
    def _getChildren(self,zeepType):
        c = (getattr(getattr(zeepType,"type",None),"elements_nested",[]) or
            getattr(zeepType,"elements_nested",[]))
        if len(c)>0 and isinstance(c[0],tuple): c = [v for k,v in c]
        #if zeepType.accepts_multiple:
        attributes = getattr(getattr(zeepType,"type",None),"attributes",[])
        attributes = [v for k,v in attributes]
        c = c+attributes
        return c
    
    def _func_leaf_default(zeepType,*args): return {zeepType.name:zeepType}

    def _func_root_default(zeepType,parent,includeOptionalArgs,func_leaf,func_root):
        val = {k:v for e in WsdlTreeParser._getChildren(zeepType) 
                           for k,v in WsdlTreeParser._walkZeepType(e,zeepType,includeOptionalArgs,func_leaf,func_root).items()}
        if zeepType.name is None: return val
        return {zeepType.name: val}
    
    @classmethod
    def _walkZeepType(self,zeepType,parent=None,includeOptionalArgs=False,
            func_leaf=_func_leaf_default,func_root=_func_root_default):
        """
        Parse zeepType wsdl tree and output dict
        """
        #if zeepType.name == 'UseVerificationTime':
        #    import ipdb;ipdb.set_trace()
        if (not includeOptionalArgs and getattr(zeepType,"is_optional",False)
                and not isinstance(zeepType,Choice)):
            return {}
        
        if zeepType.name in DEFAULT_VALUES: 
            return {zeepType.name:DEFAULT_VALUES[zeepType.name]}

        if not self._getChildren(zeepType):
            # tree leaf
            return func_leaf(zeepType,parent,includeOptionalArgs,func_leaf,func_root)
        # tree root
        return func_root(zeepType,parent,includeOptionalArgs,func_leaf,func_root)

    @classmethod
    def zeepTypeToDict(self,zeepType,*args,**xargs):
        v = self._walkZeepType(zeepType,None,*args,**xargs).values()
        assert(len(v)==1)
        return list(v)[0]
    

def defaultFor(name):
    return DEFAULT_VALUES.get(name,DEFAULT_VALUE)

def leaf2val(zeepType,*args):
    name = zeepType.name
    if name is None: return {}
    accepted = zeepType.type.accepted_types
    # FILL VALUES
    if isinstance(zeepType.type,zeep.xsd.types.builtins.Base64Binary): 
        return {name:"dGVzdA==".encode("utf-8")}#{name:bytes(1)}
    #elif str in accepted and zeepType.is_optional: return {name:"§§"}
    elif str in accepted: return {name:str(defaultFor(name))}
    elif datetime.datetime in accepted: return {name:datetime.datetime.now()}
    else: return {name:defaultFor(name)}


class AllChoices(object):
    """
    Class to create a request for each choice on Choice element
    """
    s2bIdCount = 0

    @classmethod
    def each(self,v,*zeepTypeToDictArgs):
        """
        #foreach choice:
        if len(amountChoices) > 0:
            choices = [list(e) for e in list(itertools.zip_longest(*tuple([list(range(choices)) for choices in amountChoices]),fillvalue=0))]
        else: choices = [None]
        """
        #passes = max([len(options) for Id, options in choices.items()]) \
        #    if len(choices) > 0 else 1

        # node = Choice object
        # edge = choice option

        #global choices
        completePaths = []
        choices = []
        def walkChoices():
            global cancel
            cancel = False
            def funcRoot_discoverNodes(zeepType,*args):
                global cancel
                if cancel: return {}
                if not isinstance(zeepType, Choice): 
                    return WsdlTreeParser._func_root_default(zeepType,*args)
                if not getattr(zeepType,"s2bId",None) in dict(choices): 
                    # new node discovered
                    zeepType.s2bId = self.s2bIdCount
                    self.s2bIdCount += 1
                    options = WsdlTreeParser._getChildren(zeepType)
                    choices.append((zeepType.s2bId,options))
                    
                    while len(options) > 0: # walk all paths
                        walkChoices() # recursive call
                        if len(options) <= 1: break
                        options.pop(0) # edge done

                    cancel = True;return {} # return from walkChoices
                else:
                    # select edge
                    options = dict(choices)[zeepType.s2bId]
                    zeepType = options[0] if options else \
                        WsdlTreeParser._getChildren(zeepType)[0]
                    return WsdlTreeParser._walkZeepType(zeepType,*args)
                
            WsdlTreeParser.zeepTypeToDict(v,*zeepTypeToDictArgs,func_root=funcRoot_discoverNodes) #exec
            if not cancel: 
                path = {Id:options[0] for Id,options in choices}
                completePaths.append(path)
        walkChoices()
        
        for path in completePaths:
            def funcRoot_chosenPath(zeepType, *args):
                if isinstance(zeepType, Choice):
                    # select edge
                    zeepType = path[zeepType.s2bId]
                    return WsdlTreeParser._walkZeepType(zeepType,*args)
                return WsdlTreeParser._func_root_default(zeepType,*args)
            yield funcRoot_chosenPath # walk complete tree


for wsdl in sys.argv[1:]:
    print("WSDL: %s\n"%wsdl)

    client = Client(wsdl, settings=Settings(strict=False, forbid_entities=False))
    if PROXY: client.transport.session.proxies = dict(http=PROXY,https=PROXY)

    globalWsdlMethods = dir(client.service)
    wsdlMethods = [(e.name, e) 
        for e in client.wsdl.types.elements if e.name in globalWsdlMethods]

    # correcting URL
    base = os.path.splitext(os.path.basename(wsdl))[0].lower()
    qname = list(client.wsdl.bindings.keys())[0]
    service = client.create_service(qname,"%s/%s"%(SOAP,base))
        
    for k,v in wsdlMethods:
        print(" - Method '%s':\n\tSignature: %s"
            %(k,v.signature()))

        for includeOptionalArgs in set([INCLUDE_OPTIONAL_ARGUMENTS, False]):
            for choose_func in AllChoices.each(v,includeOptionalArgs):
                try: d = WsdlTreeParser.zeepTypeToDict(v,includeOptionalArgs,func_root=choose_func,func_leaf=leaf2val)
                except Exception as e:
                    print(repr(e))
                    continue
                
                print("\tCall: %s"%d)
                sys.stdout.write("\tResult: ")
                try: getattr(service,k)(**d)
                except Exception as e: 
                    if "Fault" in repr(e): sys.stdout.write(WARNING)
                    else: sys.stdout.write(FAIL)
                    print("%s"%repr(e)+ENDC)
                else: print(OKC+"ok"+ENDC)
                print("\n")
        
    print("\n\n")


