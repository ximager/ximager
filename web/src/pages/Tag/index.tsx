import axios from "axios";
import { useParams } from 'react-router-dom';
import { useSearchParams } from 'react-router-dom';
import { Fragment, useEffect, useState } from "react";
import { Helmet, HelmetProvider } from 'react-helmet-async';
import relativeTime from 'dayjs/plugin/relativeTime';
import dayjs from 'dayjs';

import Menu from "../../components/Menu";
import Header from "../../components/Header";
import Pagination from "../../components/Pagination";
import Settings from "../../Settings";

import TableItem from "./TableItem";
import "./index.css";

import { ITag, ITagList, IHTTPError } from "../../interfaces/interfaces";

export default function Tag({ localServer }: { localServer: string }) {
  let [tagList, setTagList] = useState<ITagList>({} as ITagList);
  let [refresh, setRefresh] = useState({});
  let [pageNum, setPageNum] = useState(1);
  let [searchRepository, setSearchRepository] = useState("");
  let [total, setTotal] = useState(0);

  const { namespace } = useParams<{ namespace: string }>();
  const [searchParams] = useSearchParams();
  const repository = searchParams.get('repository');

  useEffect(() => {
    let url = localServer + `/namespace/${namespace}/tag/?repository=${repository}&page_size=${Settings.PageSize}&page_num=${pageNum}`;
    if (searchRepository !== "") {
      url += `&name=${searchRepository}`;
    }
    axios.get(url)
      .then((response) => {
        if (response.status === 200) {
          let tagList = response.data as ITagList;
          setTagList(tagList);
          setTotal(tagList.total);
        }
      });
  }, [refresh, pageNum]);

  return (
    <Fragment>
      <HelmetProvider>
        <Helmet>
          <title>XImager - Tag</title>
        </Helmet>
      </HelmetProvider>
      <div className="min-h-screen flex overflow-hidden bg-white">
        <Menu item="Tag" />
        <div className="flex flex-col w-0 flex-1 overflow-hidden">
          <main className="flex-1 relative z-0 focus:outline-none" tabIndex={0}>
            <Header title="Tag" />
            <div className="hidden sm:block">
              <div className="align-middle inline-block min-w-full border-b border-gray-200">
                <table className="min-w-full">
                  <thead>
                    <tr className="border-gray-200">
                      <th className="px-6 py-3 border-b border-gray-200 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        <span className="lg:pl-2">Tag</span>
                      </th>
                      <th className="hidden md:table-cell px-6 py-3 border-b border-gray-200 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                        Digest
                      </th>
                      <th className="hidden md:table-cell px-6 py-3 border-b border-gray-200 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                        Size
                      </th>
                      <th className="hidden md:table-cell px-6 py-3 border-b border-gray-200 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Create
                      </th>
                      <th className="hidden md:table-cell px-6 py-3 border-b border-gray-200 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Update
                      </th>
                      <th className="pr-6 py-3 border-b border-gray-200 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-100">
                    {
                      tagList.items?.map(m => {
                        return (
                          <TableItem key={m.id} id={m.id} namespace={namespace} repository={repository} name={m.name} digest={m.digest} size={m.size} created_at={m.created_at} updated_at={m.updated_at} />
                        );
                      })
                    }
                  </tbody>
                </table>
              </div>
            </div>
          </main>
          <Pagination page_size={Settings.PageSize} page_num={pageNum} setPageNum={setPageNum} total={total} />
        </div>
      </div>
    </Fragment >
  )
}
