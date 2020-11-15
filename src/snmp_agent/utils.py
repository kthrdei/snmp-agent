from typing import List

from . import snmp


def handle_request(req: snmp.SNMPRequest, 
                   vbs: List[snmp.VariableBinding]) -> List[snmp.VariableBinding]:
    if isinstance(req.context, snmp.SnmpGetContext):
        results = get(req_vbs=req.variable_bindings, vbs=vbs)
    elif isinstance(req.context, snmp.SnmpGetNextContext):
        results = get_next(req_vbs=req.variable_bindings, vbs=vbs)
    elif isinstance(req.context, snmp.SnmpGetBulkContext):
        results = get_bulk(req_vbs=req.variable_bindings, 
                           non_repeaters=req.non_repeaters,
                           max_repetitions=req.max_repetitions,
                           vbs=vbs)
    else:
        raise NotImplementedError
    return results


def get(req_vbs: List[snmp.VariableBinding], 
        vbs: List[snmp.VariableBinding]) -> List[snmp.VariableBinding]:
    results: List[snmp.VariableBinding] = []
    for req_vb in req_vbs:
        _results = [vb for vb in vbs if req_vb.oid == vb.oid]
        if _results:
            _result = _results[0]
        else:
            _result = snmp.VariableBinding(
                oid=req_vb.oid, 
                value=snmp.NoSuchObject())
        results.append(_result)
    return results


def get_next(req_vbs: List[snmp.VariableBinding], 
             vbs: List[snmp.VariableBinding]) -> snmp.List[snmp.VariableBinding]:
    sorted_vbs = sorted(vbs, key=lambda x: [int(o) for o in x.oid.split('.')])
    results: List[snmp.VariableBinding] = []
    for req_vb in req_vbs:
        next_vb = snmp.VariableBinding(
            oid=req_vb.oid, 
            value=snmp.EndOfMibView())
        for vb in sorted_vbs:
            if [int(o) for o in req_vb.oid.split('.')] < [int(o) for o in vb.oid.split('.')]:
                next_vb.oid = vb.oid
                next_vb.value = vb.value
                break
        results.append(next_vb)
    return results


def get_bulk(req_vbs: List[snmp.VariableBinding], 
             non_repeaters: int,
             max_repetitions: int,
             vbs: List[snmp.VariableBinding]) -> List[snmp.VariableBinding]:
    # non_repeaters
    _req_vbs = req_vbs[:non_repeaters]
    results = get_next(req_vbs=_req_vbs, vbs=vbs)
    # max_repetitions
    _req_vbs = req_vbs[non_repeaters:]
    for _ in range(max_repetitions):
        for index, req_vb in enumerate(_req_vbs):
            _results = get_next(req_vbs=[req_vb], vbs=vbs)
            _result = _results[0]
            results.append(_result)
            _req_vbs[index] = snmp.VariableBinding(
                oid=_result.oid, 
                value=snmp.Null())
    return results
