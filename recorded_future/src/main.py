from datetime import datetime

from common import ingest, utils
from models import DefaultRiskList, _GlobalTimeHolder
from psengine.config import Config
from psengine.risklists import RisklistMgr
from time_helper import rel_time_to_date
from version import __version__

RECORDED_FUTURE_SECRET = 'RECORDED_FUTURE_SECRET'
RECORDED_FUTURE_IOC_TYPE = 'RECORDED_FUTURE_IOC_TYPE'

RECORDED_FUTURE_OFFSET = 'RECORDED_FUTURE_OFFSET'
FUSION_PATH_DOMAIN = 'RECORDED_FUTURE_FUSION_PATH_DOMAIN'
FUSION_PATH_IP = 'RECORDED_FUTURE_FUSION_PATH_IP'
FUSION_PATH_HASH = 'RECORDED_FUTURE_FUSION_PATH_HASH'
FUSION_PATH_URL = 'RECORDED_FUTURE_FUSION_PATH_URL'

LOG_TYPE = 'RECORDED_FUTURE_IOC'


def ingest_risklist(risklist_mgr, ioc_type, list_name='default'):
    ingest_start = f'{datetime.now().isoformat(timespec="seconds")}Z'
    ingest_end = rel_time_to_date(utils.get_env_var(RECORDED_FUTURE_OFFSET), ingest_start)
    ingest_end = rel_time_to_date('1h', ingest_end)

    _GlobalTimeHolder.set_ingestion_times(ingest_start, ingest_end)
    try:
        if list_name == 'default':
            risks = risklist_mgr.fetch_risklist(list_name, ioc_type, validate=DefaultRiskList)
        else:
            risks = risklist_mgr.fetch_risklist(list_name, validate=DefaultRiskList)

    except Exception as e:  # noqa: BLE001
        print(f'The risklist for {ioc_type} cannot be ingested. Error: {e}')
        return

    try:
        ingest.ingest(
            [r.model_dump(by_alias=True, exclude_none=True) for r in risks], log_type=LOG_TYPE
        )
    except RuntimeError as r:
        print(f'Error ingesting {ioc_type} for list {list_name}, will move on. Error: {r}.')


def main(request=None):  # noqa: ARG001
    Config.init(app_id=f'ps-google-siem/{__version__}')
    risklist_mgr = RisklistMgr(utils.get_env_var(RECORDED_FUTURE_SECRET, is_secret=True))

    domain_fusion = utils.get_env_var(FUSION_PATH_DOMAIN, required=False, default='default')
    ip_fusion = utils.get_env_var(FUSION_PATH_IP, required=False, default='default')
    url_fusion = utils.get_env_var(FUSION_PATH_URL, required=False, default='default')
    hash_fusion = utils.get_env_var(FUSION_PATH_HASH, required=False, default='default')
    list_details = {
        'domain': domain_fusion,
        'ip': ip_fusion,
        'hash': hash_fusion,
        'url': url_fusion,
    }
    print(list_details)
    for entity_type, list_name in list_details.items():
        print(f'Ingesting {entity_type}')
        ingest_risklist(risklist_mgr, entity_type, list_name)

    return 'Ingestion completed.'


if __name__ == '__main__':
    main()
